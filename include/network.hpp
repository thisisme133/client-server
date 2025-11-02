#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <string_view>
#include <concepts>
#include <expected>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif

namespace net {

// Concepts
template<typename T>
concept SocketType = std::same_as<T, socket_t>;

template<typename T>
concept AddressType = requires(T addr) {
    { addr.sin_family } -> std::convertible_to<uint16_t>;
    { addr.sin_port } -> std::convertible_to<uint16_t>;
};

// Error handling
enum class Error : int32_t {
    None = 0,
    InitFailed,
    CreateFailed,
    BindFailed,
    ListenFailed,
    ConnectFailed,
    SendFailed,
    RecvFailed,
    InvalidSocket,
    WouldBlock
};

// RAII Socket wrapper
class Socket {
    socket_t fd_ = INVALID_SOCKET_VALUE;

public:
    constexpr Socket() noexcept = default;
    explicit Socket(socket_t fd) noexcept : fd_(fd) {}
    ~Socket() noexcept { close(); }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : fd_(other.fd_) {
        other.fd_ = INVALID_SOCKET_VALUE;
    }

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            other.fd_ = INVALID_SOCKET_VALUE;
        }
        return *this;
    }

    [[nodiscard]] constexpr socket_t get() const noexcept { return fd_; }
    [[nodiscard]] constexpr bool valid() const noexcept { return fd_ != INVALID_SOCKET_VALUE; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return valid(); }

    void close() noexcept;
    [[nodiscard]] socket_t release() noexcept {
        auto fd = fd_;
        fd_ = INVALID_SOCKET_VALUE;
        return fd;
    }

    // Operations
    [[nodiscard]] std::expected<void, Error> set_nonblocking() noexcept;
    [[nodiscard]] std::expected<size_t, Error> send(std::span<const uint8_t> data) noexcept;
    [[nodiscard]] std::expected<size_t, Error> recv(std::span<uint8_t> buffer) noexcept;
};

// Network Manager
class NetworkManager {
    bool initialized_ = false;

    NetworkManager() = default;
    ~NetworkManager();

public:
    static NetworkManager& instance() {
        static NetworkManager mgr;
        return mgr;
    }

    NetworkManager(const NetworkManager&) = delete;
    NetworkManager& operator=(const NetworkManager&) = delete;

    [[nodiscard]] std::expected<void, Error> init() noexcept;
    void cleanup() noexcept;
};

// Free functions
[[nodiscard]] std::expected<Socket, Error> create_socket() noexcept;
[[nodiscard]] std::expected<Socket, Error> connect(std::string_view ip, uint16_t port) noexcept;
[[nodiscard]] std::expected<void, Error> bind(socket_t fd, uint16_t port) noexcept;
[[nodiscard]] std::expected<void, Error> listen(socket_t fd, int backlog) noexcept;
[[nodiscard]] std::expected<Socket, Error> accept(socket_t fd, std::array<char, 46>& ip, uint16_t& port) noexcept;

[[nodiscard]] constexpr bool would_block() noexcept {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

} // namespace net
