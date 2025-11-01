#include "network.h"
#include "packet.h"
#include "compression.h"
#include <stdio.h>
#include <string.h>

#define MAX_CLIENTS 32
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048

typedef struct {
    socket_t socket;
    uint8_t active;
    char ip[16];
    uint16_t port;
} client_info_t;

static client_info_t clients[MAX_CLIENTS];
static socket_t server_socket = INVALID_SOCKET_VALUE;

/* Forward declarations des handlers */
static void handle_connect(uint8_t client_id);
static void handle_disconnect(uint8_t client_id, uint8_t reason);
static void handle_packet(uint8_t client_id, packet_t* pkt);

/* Handlers spécifiques par type de packet */
static void handle_ping(uint8_t client_id, packet_t* pkt);
static void handle_message(uint8_t client_id, packet_t* pkt);
static void handle_data(uint8_t client_id, packet_t* pkt);

/* Utilitaires */
static int8_t find_free_slot(void);
static void remove_client(uint8_t client_id);
static void send_packet_to_client(uint8_t client_id, packet_t* pkt);

int main(void) {
    printf("TCP Server - Starting...\n");

    /* Initialiser réseau */
    if (net_init() != 0) {
        printf("Error: Failed to initialize network\n");
        return 1;
    }

    /* Créer socket */
    server_socket = net_create_socket();
    if (server_socket == INVALID_SOCKET_VALUE) {
        printf("Error: Failed to create socket\n");
        net_cleanup();
        return 1;
    }

    /* Configuration socket */
    net_set_reuse_addr(server_socket);
    net_set_nonblocking(server_socket);

    /* Bind */
    if (net_bind(server_socket, SERVER_PORT) != 0) {
        printf("Error: Failed to bind to port %d\n", SERVER_PORT);
        net_close_socket(server_socket);
        net_cleanup();
        return 1;
    }

    /* Listen */
    if (net_listen(server_socket, 10) != 0) {
        printf("Error: Failed to listen\n");
        net_close_socket(server_socket);
        net_cleanup();
        return 1;
    }

    printf("Server listening on port %d\n", SERVER_PORT);

    /* Initialiser clients */
    memset(clients, 0, sizeof(clients));
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = INVALID_SOCKET_VALUE;
    }

    /* Boucle principale */
    uint8_t buffer[BUFFER_SIZE];
    while (1) {
        /* Accepter nouvelles connexions */
        char ip[16];
        uint16_t port;
        socket_t new_client = net_accept(server_socket, ip, &port);

        if (new_client != INVALID_SOCKET_VALUE) {
            int8_t slot = find_free_slot();
            if (slot >= 0) {
                clients[slot].socket = new_client;
                clients[slot].active = 1;
                strncpy(clients[slot].ip, ip, 16);
                clients[slot].port = port;
                net_set_nonblocking(new_client);
                handle_connect(slot);
            } else {
                printf("Warning: Max clients reached, rejecting connection\n");
                net_close_socket(new_client);
            }
        }

        /* Traiter les clients existants */
        for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) continue;

            int32_t received = net_recv(clients[i].socket, buffer, BUFFER_SIZE);

            if (received > 0) {
                /* Désérialiser et traiter le packet */
                packet_t pkt;
                uint16_t consumed = pkt_deserialize(&pkt, buffer, received);

                if (consumed > 0) {
                    /* Décompresser si nécessaire */
                    if (pkt_has_flag(&pkt, PKT_FLAG_COMPRESSED)) {
                        uint8_t decompressed[MAX_PAYLOAD_SIZE];
                        uint16_t decompressed_size = decompress_data(
                            pkt.payload, pkt.header.length,
                            decompressed, MAX_PAYLOAD_SIZE);
                        memcpy(pkt.payload, decompressed, decompressed_size);
                        pkt.header.length = decompressed_size;
                        pkt.header.flags &= ~PKT_FLAG_COMPRESSED;
                    }

                    handle_packet(i, &pkt);
                }
            } else if (received == 0) {
                /* Connexion fermée */
                handle_disconnect(i, 0);
                remove_client(i);
            } else if (!net_would_block()) {
                /* Erreur */
                handle_disconnect(i, 1);
                remove_client(i);
            }
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Cleanup */
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            net_close_socket(clients[i].socket);
        }
    }
    net_close_socket(server_socket);
    net_cleanup();

    return 0;
}

static void handle_connect(uint8_t client_id) {
    printf("Client %d connected: %s:%d\n",
           client_id, clients[client_id].ip, clients[client_id].port);

    /* Envoyer packet ACK */
    packet_t pkt;
    pkt_init(&pkt, PKT_ACK);
    send_packet_to_client(client_id, &pkt);
}

static void handle_disconnect(uint8_t client_id, uint8_t reason) {
    printf("Client %d disconnected (reason: %d)\n", client_id, reason);
}

static void handle_packet(uint8_t client_id, packet_t* pkt) {
    /* Switch case pour router vers les handlers spécifiques */
    switch (pkt_get_type(pkt)) {
        case PKT_CONNECT:
            printf("Client %d: CONNECT packet\n", client_id);
            break;

        case PKT_DISCONNECT:
            printf("Client %d: DISCONNECT packet\n", client_id);
            remove_client(client_id);
            break;

        case PKT_PING:
            handle_ping(client_id, pkt);
            break;

        case PKT_MESSAGE:
            handle_message(client_id, pkt);
            break;

        case PKT_DATA:
            handle_data(client_id, pkt);
            break;

        default:
            printf("Client %d: Unknown packet type %d\n", client_id, pkt_get_type(pkt));
            break;
    }
}

static void handle_ping(uint8_t client_id, packet_t* pkt) {
    (void)pkt;  /* Paramètre non utilisé */
    printf("Client %d: PING\n", client_id);

    /* Répondre avec PONG */
    packet_t pong;
    pkt_init(&pong, PKT_PONG);
    send_packet_to_client(client_id, &pong);
}

static void handle_message(uint8_t client_id, packet_t* pkt) {
    payload_message_t msg;
    uint16_t size;
    pkt_get_payload(pkt, &msg, &size);

    printf("Client %d: MESSAGE [%.*s]\n", client_id, msg.msg_len, msg.message);

    /* Echo le message */
    send_packet_to_client(client_id, pkt);
}

static void handle_data(uint8_t client_id, packet_t* pkt) {
    payload_data_t data;
    uint16_t size;
    pkt_get_payload(pkt, &data, &size);

    printf("Client %d: DATA (%d bytes)\n", client_id, data.data_len);

    /* Envoyer ACK */
    packet_t ack;
    pkt_init(&ack, PKT_ACK);
    send_packet_to_client(client_id, &ack);
}

static int8_t find_free_slot(void) {
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) return i;
    }
    return -1;
}

static void remove_client(uint8_t client_id) {
    if (clients[client_id].active) {
        net_close_socket(clients[client_id].socket);
        clients[client_id].active = 0;
        clients[client_id].socket = INVALID_SOCKET_VALUE;
    }
}

static void send_packet_to_client(uint8_t client_id, packet_t* pkt) {
    if (!clients[client_id].active) return;

    /* Compresser si bénéfique */
    if (should_compress(pkt->payload, pkt->header.length)) {
        uint8_t compressed[MAX_PAYLOAD_SIZE];
        uint16_t compressed_size = compress_data(
            pkt->payload, pkt->header.length,
            compressed, MAX_PAYLOAD_SIZE);

        if (compressed_size < pkt->header.length) {
            memcpy(pkt->payload, compressed, compressed_size);
            pkt->header.length = compressed_size;
            pkt_set_flag(pkt, PKT_FLAG_COMPRESSED);
        }
    }

    /* Sérialiser et envoyer */
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);
    net_send(clients[client_id].socket, buffer, size);
}
