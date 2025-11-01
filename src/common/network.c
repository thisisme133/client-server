#include "network.h"
#include <string.h>

#ifdef _WIN32
    #include <errno.h>
#else
    #include <errno.h>
#endif

int8_t net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) ? 0 : -1;
#else
    return 0;
#endif
}

void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

socket_t net_create_socket(void) {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void net_close_socket(socket_t sock) {
    if (sock != INVALID_SOCKET_VALUE) {
        closesocket(sock);
    }
}

int8_t net_set_nonblocking(socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0) ? 0 : -1;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0) ? 0 : -1;
#endif
}

int8_t net_set_reuse_addr(socket_t sock) {
    int opt = 1;
    return (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == 0) ? 0 : -1;
}

int8_t net_bind(socket_t sock, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    return (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) ? 0 : -1;
}

int8_t net_listen(socket_t sock, int32_t backlog) {
    return (listen(sock, backlog) == 0) ? 0 : -1;
}

socket_t net_accept(socket_t sock, char* client_ip, uint16_t* client_port) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    socket_t client = accept(sock, (struct sockaddr*)&addr, &addr_len);

    if (client != INVALID_SOCKET_VALUE && client_ip && client_port) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, 16);
        *client_port = ntohs(addr.sin_port);
    }

    return client;
}

int8_t net_connect(socket_t sock, const char* ip, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        return -1;
    }

    return (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) ? 0 : -1;
}

int32_t net_send(socket_t sock, const void* data, uint16_t size) {
    return (int32_t)send(sock, (const char*)data, size, 0);
}

int32_t net_recv(socket_t sock, void* buffer, uint16_t size) {
    return (int32_t)recv(sock, (char*)buffer, size, 0);
}

int8_t net_would_block(void) {
#ifdef _WIN32
    return (WSAGetLastError() == WSAEWOULDBLOCK) ? 1 : 0;
#else
    return (errno == EWOULDBLOCK || errno == EAGAIN) ? 1 : 0;
#endif
}
