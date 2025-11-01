#include "network.h"
#include "packet.h"
#include "compression.h"
#include "crc.h"
#include "crypto.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
    typedef HANDLE thread_t;
    #define thread_create(thread, func, arg) \
        (*(thread) = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL))
    #define thread_join(thread) WaitForSingleObject(thread, INFINITE)
    typedef unsigned int (__stdcall *thread_func_t)(void*);
    #define THREAD_RETURN unsigned int __stdcall
#else
    #include <pthread.h>
    #include <unistd.h>
    typedef pthread_t thread_t;
    #define thread_create(thread, func, arg) pthread_create(thread, NULL, func, arg)
    #define thread_join(thread) pthread_join(thread, NULL)
    typedef void* (*thread_func_t)(void*);
    #define THREAD_RETURN void*
#endif

#define MAX_CLIENTS 32
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048
#define HEARTBEAT_TIMEOUT 10  /* 10 secondes */

typedef struct {
    socket_t socket;
    uint8_t active;
    uint8_t authenticated;
    char ip[16];
    uint16_t port;
    uint32_t current_challenge;
    uint8_t session_key[SESSION_KEY_SIZE];
    time_t last_heartbeat;
    thread_t thread;
} client_info_t;

static client_info_t clients[MAX_CLIENTS];
static socket_t server_socket = INVALID_SOCKET_VALUE;

/* Prototypes */
static THREAD_RETURN client_thread(void* arg);
static void handle_packet(uint8_t client_id, packet_t* pkt);
static void send_packet_to_client(uint8_t client_id, packet_t* pkt, uint8_t encrypt);
static void send_challenge(uint8_t client_id);
static void send_session_key(uint8_t client_id);
static void check_heartbeat_timeout(void);

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("    TCP Multi-threaded Server with Authentication\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    logger_init();

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

    printf("✓ Server listening on port %d\n\n", SERVER_PORT);

    /* Initialiser clients */
    memset(clients, 0, sizeof(clients));
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = INVALID_SOCKET_VALUE;
    }

    /* Boucle principale d'acceptation */
    while (1) {
        /* Accepter nouvelle connexion */
        char ip[16];
        uint16_t port;
        socket_t new_socket = net_accept(server_socket, ip, &port);

        if (new_socket != INVALID_SOCKET_VALUE) {
            /* Trouver un slot libre */
            int8_t slot = -1;
            for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
                if (!clients[i].active) {
                    slot = i;
                    break;
                }
            }

            if (slot >= 0) {
                clients[slot].socket = new_socket;
                clients[slot].active = 1;
                clients[slot].authenticated = 0;
                strncpy(clients[slot].ip, ip, 16);
                clients[slot].port = port;
                clients[slot].last_heartbeat = time(NULL);

                /* Générer challenge et clé de session */
                clients[slot].current_challenge = crypto_generate_challenge();
                crypto_generate_session_key(clients[slot].session_key, SESSION_KEY_SIZE);

                printf("✓ Client %d connected from %s:%d\n", slot, ip, port);

                /* Créer thread pour ce client */
                thread_create(&clients[slot].thread, client_thread, (void*)(intptr_t)slot);
            } else {
                printf("✗ Max clients reached, rejecting connection\n");
                net_close_socket(new_socket);
            }
        }

        /* Vérifier les timeouts heartbeat */
        check_heartbeat_timeout();

#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }

    /* Cleanup */
    net_close_socket(server_socket);
    net_cleanup();
    return 0;
}

static THREAD_RETURN client_thread(void* arg) {
    uint8_t client_id = (uint8_t)(intptr_t)arg;
    uint8_t buffer[BUFFER_SIZE];

    printf("→ Thread started for client %d\n", client_id);

    /* Envoyer challenge */
    send_challenge(client_id);

    /* Envoyer clé de session */
    send_session_key(client_id);

    /* Boucle de réception */
    while (clients[client_id].active) {
        int32_t received = net_recv(clients[client_id].socket, buffer, BUFFER_SIZE);

        if (received > 0) {
            /* Désérialiser packet */
            packet_t pkt;
            uint16_t consumed = pkt_deserialize(&pkt, buffer, received);

            if (consumed > 0) {
                char peer_info[32];
                snprintf(peer_info, sizeof(peer_info), "%s:%d",
                         clients[client_id].ip, clients[client_id].port);
                log_packet(LOG_RECV, &pkt, peer_info);

                /* Déchiffrer si nécessaire */
                if (pkt_has_flag(&pkt, PKT_FLAG_ENCRYPTED) && clients[client_id].authenticated) {
                    crypto_decrypt(clients[client_id].session_key,
                                 pkt.payload, pkt.payload, pkt.header.length);
                    pkt.header.flags &= ~PKT_FLAG_ENCRYPTED;
                }

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

                handle_packet(client_id, &pkt);
            } else {
                printf("✗ Client %d: Invalid packet (CRC fail or malformed)\n", client_id);
            }
        } else if (received == 0) {
            printf("← Client %d disconnected\n", client_id);
            break;
        } else if (!net_would_block()) {
            printf("✗ Client %d: Connection error\n", client_id);
            break;
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Cleanup */
    net_close_socket(clients[client_id].socket);
    clients[client_id].active = 0;
    clients[client_id].socket = INVALID_SOCKET_VALUE;

    printf("✓ Thread stopped for client %d\n", client_id);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void handle_packet(uint8_t client_id, packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CONNECT: {
            /* Client demande authentification (déjà envoyé challenge/key) */
            clients[client_id].authenticated = 1;
            packet_t ack;
            pkt_init(&ack, PKT_ACK);
            send_packet_to_client(client_id, &ack, 0);
            break;
        }

        case PKT_HEARTBEAT: {
            payload_heartbeat_t hb;
            uint16_t size;
            pkt_get_payload(pkt, &hb, &size);

            /* Vérifier la réponse au challenge */
            uint32_t expected = crypto_solve_challenge(clients[client_id].current_challenge);

            if (hb.challenge_response == expected) {
                clients[client_id].last_heartbeat = time(NULL);

                /* Envoyer nouveau challenge */
                clients[client_id].current_challenge = crypto_generate_challenge();
                send_challenge(client_id);
            } else {
                printf("✗ Client %d: Invalid heartbeat response\n", client_id);
                packet_t err;
                pkt_init(&err, PKT_ERROR);
                payload_error_t payload;
                payload.error_code = 1;
                strncpy(payload.error_msg, "Invalid heartbeat challenge", 127);
                pkt_set_payload(&err, &payload, sizeof(payload));
                send_packet_to_client(client_id, &err, 0);
            }
            break;
        }

        case PKT_PING: {
            packet_t pong;
            pkt_init(&pong, PKT_PONG);
            send_packet_to_client(client_id, &pong, 1);
            break;
        }

        case PKT_MESSAGE: {
            /* Echo le message chiffré */
            send_packet_to_client(client_id, pkt, 1);
            break;
        }

        case PKT_DISCONNECT: {
            printf("Client %d requested disconnect\n", client_id);
            clients[client_id].active = 0;
            break;
        }

        default:
            printf("Client %d: Unknown packet type %d\n", client_id, pkt_get_type(pkt));
            break;
    }
}

static void send_packet_to_client(uint8_t client_id, packet_t* pkt, uint8_t encrypt) {
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

    /* Chiffrer si demandé et authentifié */
    if (encrypt && clients[client_id].authenticated) {
        crypto_encrypt(clients[client_id].session_key,
                      pkt->payload, pkt->payload, pkt->header.length);
        pkt_set_flag(pkt, PKT_FLAG_ENCRYPTED);
    }

    /* Sérialiser et envoyer */
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);

    char peer_info[32];
    snprintf(peer_info, sizeof(peer_info), "%s:%d",
             clients[client_id].ip, clients[client_id].port);
    log_packet(LOG_SEND, pkt, peer_info);

    net_send(clients[client_id].socket, buffer, size);
}

static void send_challenge(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_CHALLENGE);

    payload_challenge_t payload;
    payload.challenge = clients[client_id].current_challenge;

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 0);
}

static void send_session_key(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_SESSION_KEY);

    payload_session_key_t payload;
    memcpy(payload.key, clients[client_id].session_key, SESSION_KEY_SIZE);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 0);
}

static void check_heartbeat_timeout(void) {
    time_t now = time(NULL);

    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].authenticated) {
            if (difftime(now, clients[i].last_heartbeat) > HEARTBEAT_TIMEOUT) {
                printf("✗ Client %d: Heartbeat timeout\n", i);
                clients[i].active = 0;
            }
        }
    }
}
