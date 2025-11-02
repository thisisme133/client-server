#include "network.hpp"
#include <cstring>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#else
#include <fcntl.h>
#endif

namespace net {

// Socket implementation
void Socket::close() noexcept {
    if (fd_ != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        closesocket(fd_);
#else
        ::close(fd_);
#endif
        fd_ = INVALID_SOCKET_VALUE;
    }
}

std::expected<void, Error> Socket::set_nonblocking() noexcept {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(fd_, FIONBIO, &mode) != 0) {
        return std::unexpected(Error::InvalidSocket);
    }
#else
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags == -1) return std::unexpected(Error::InvalidSocket);
    if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) == -1) {
        return std::unexpected(Error::InvalidSocket);
    }
#endif
    return {};
}

std::expected<size_t, Error> Socket::send(std::span<const uint8_t> data) noexcept {
    if (!valid()) return std::unexpected(Error::InvalidSocket);

#ifdef _WIN32
    int result = ::send(fd_, reinterpret_cast<const char*>(data.data()),
                       static_cast<int>(data.size()), 0);
#else
    ssize_t result = ::send(fd_, data.data(), data.size(), MSG_NOSIGNAL);
#endif

    if (result < 0) {
        return would_block() ? std::expected<size_t, Error>(0)
                            : std::unexpected(Error::SendFailed);
    }

    return static_cast<size_t>(result);
}

std::expected<size_t, Error> Socket::recv(std::span<uint8_t> buffer) noexcept {
    if (!valid()) return std::unexpected(Error::InvalidSocket);

#ifdef _WIN32
    int result = ::recv(fd_, reinterpret_cast<char*>(buffer.data()),
                       static_cast<int>(buffer.size()), 0);
#else
    ssize_t result = ::recv(fd_, buffer.data(), buffer.size(), 0);
#endif

    if (result < 0) {
        return would_block() ? std::expected<size_t, Error>(0)
                            : std::unexpected(Error::RecvFailed);
    }

    if (result == 0) {
        return std::unexpected(Error::RecvFailed);  // Connection closed
    }

    return static_cast<size_t>(result);
}

// NetworkManager implementation
NetworkManager::~NetworkManager() {
    cleanup();
}

std::expected<void, Error> NetworkManager::init() noexcept {
    if (initialized_) return {};

#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return std::unexpected(Error::InitFailed);
    }
#endif

    initialized_ = true;
    return {};
}

void NetworkManager::cleanup() noexcept {
    if (!initialized_) return;

#ifdef _WIN32
    WSACleanup();
#endif

    initialized_ = false;
}

// Free functions
std::expected<Socket, Error> create_socket() noexcept {
    socket_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET_VALUE) {
        return std::unexpected(Error::CreateFailed);
    }

    return Socket(fd);
}

std::expected<Socket, Error> connect(std::string_view ip, uint16_t port) noexcept {
    auto socket_result = create_socket();
    if (!socket_result) return std::unexpected(socket_result.error());

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

#ifdef _WIN32
    addr.sin_addr.S_un.S_addr = inet_addr(ip.data());
#else
    if (inet_pton(AF_INET, ip.data(), &addr.sin_addr) <= 0) {
        return std::unexpected(Error::ConnectFailed);
    }
#endif

    if (::connect(socket_result->get(), reinterpret_cast<sockaddr*>(&addr),
                 sizeof(addr)) != 0) {
        return std::unexpected(Error::ConnectFailed);
    }

    return std::move(*socket_result);
}

std::expected<void, Error> bind(socket_t fd, uint16_t port) noexcept {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return std::unexpected(Error::BindFailed);
    }

    return {};
}

std::expected<void, Error> listen(socket_t fd, int backlog) noexcept {
    if (::listen(fd, backlog) != 0) {
        return std::unexpected(Error::ListenFailed);
    }

    return {};
}

std::expected<Socket, Error> accept(socket_t fd, std::array<char, 46>& ip, uint16_t& port) noexcept {
    sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);

    socket_t client_fd = ::accept(fd, reinterpret_cast<sockaddr*>(&addr), &addr_len);
    if (client_fd == INVALID_SOCKET_VALUE) {
        return would_block() ? std::unexpected(Error::WouldBlock)
                            : std::unexpected(Error::InvalidSocket);
    }

#ifdef _WIN32
    const char* ip_str = inet_ntoa(addr.sin_addr);
    if (ip_str) {
        std::strncpy(ip.data(), ip_str, ip.size() - 1);
    }
#else
    inet_ntop(AF_INET, &addr.sin_addr, ip.data(), ip.size());
#endif

    port = ntohs(addr.sin_port);

    return Socket(client_fd);
}

} // namespace net
