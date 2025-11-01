#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

/* Abstraction multi-plateforme pour sockets */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define SOCKET_ERROR_VALUE SOCKET_ERROR
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    typedef int socket_t;
    #define INVALID_SOCKET_VALUE -1
    #define SOCKET_ERROR_VALUE -1
    #define closesocket close
#endif

/* Initialisation/nettoyage réseau */
int8_t net_init(void);
void net_cleanup(void);

/* Création/fermeture socket */
socket_t net_create_socket(void);
void net_close_socket(socket_t sock);

/* Configuration socket */
int8_t net_set_nonblocking(socket_t sock);
int8_t net_set_reuse_addr(socket_t sock);

/* Opérations serveur */
int8_t net_bind(socket_t sock, uint16_t port);
int8_t net_listen(socket_t sock, int32_t backlog);
socket_t net_accept(socket_t sock, char* client_ip, uint16_t* client_port);

/* Opérations client */
int8_t net_connect(socket_t sock, const char* ip, uint16_t port);

/* I/O */
int32_t net_send(socket_t sock, const void* data, uint16_t size);
int32_t net_recv(socket_t sock, void* buffer, uint16_t size);

/* Utilitaires */
int8_t net_would_block(void);

#endif
