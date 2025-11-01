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
#else
    #include <unistd.h>
    #include <sys/time.h>
#endif

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048
#define HEARTBEAT_INTERVAL 5  /* 5 secondes */

static socket_t client_socket = INVALID_SOCKET_VALUE;
static uint8_t connected = 0;
static uint8_t authenticated = 0;
static uint8_t session_key[SESSION_KEY_SIZE];
static uint32_t current_challenge = 0;
static uint32_t heartbeat_sequence = 0;
static time_t last_heartbeat = 0;

/* Prototypes */
static void handle_packet(packet_t* pkt);
static void send_packet(packet_t* pkt, uint8_t encrypt);
static void send_heartbeat(void);
static void send_connect(void);

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("    TCP Client with Heartbeat Authentication\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    logger_init();

    /* Initialiser réseau */
    if (net_init() != 0) {
        printf("Error: Failed to initialize network\n");
        return 1;
    }

    /* Créer socket */
    client_socket = net_create_socket();
    if (client_socket == INVALID_SOCKET_VALUE) {
        printf("Error: Failed to create socket\n");
        net_cleanup();
        return 1;
    }

    /* Connecter au serveur */
    printf("→ Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (net_connect(client_socket, SERVER_IP, SERVER_PORT) != 0) {
        printf("✗ Failed to connect to server\n");
        net_close_socket(client_socket);
        net_cleanup();
        return 1;
    }

    printf("✓ Connected to server\n\n");
    connected = 1;

    /* Configuration non-blocking */
    net_set_nonblocking(client_socket);

    /* Boucle principale */
    uint8_t buffer[BUFFER_SIZE];
    uint32_t test_message_counter = 0;

    while (connected) {
        /* Recevoir données */
        int32_t received = net_recv(client_socket, buffer, BUFFER_SIZE);

        if (received > 0) {
            /* Traiter tous les packets dans le buffer */
            uint16_t offset = 0;
            while (offset < (uint16_t)received) {
                packet_t pkt;
                uint16_t consumed = pkt_deserialize(&pkt, buffer + offset, received - offset);

                if (consumed > 0) {
                    log_packet(LOG_RECV, &pkt, "Server");

                    /* Déchiffrer si nécessaire */
                    if (pkt_has_flag(&pkt, PKT_FLAG_ENCRYPTED) && authenticated) {
                        crypto_decrypt(session_key, pkt.payload, pkt.payload, pkt.header.length);
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

                    handle_packet(&pkt);
                    offset += consumed;
                } else {
                    printf("✗ Invalid packet (CRC fail or malformed)\n");
                    break;
                }
            }
        } else if (received == 0) {
            printf("← Server closed connection\n");
            connected = 0;
            break;
        } else if (!net_would_block()) {
            printf("✗ Connection error\n");
            connected = 0;
            break;
        }

        /* Envoyer heartbeat si nécessaire */
        if (authenticated) {
            time_t now = time(NULL);
            if (difftime(now, last_heartbeat) >= HEARTBEAT_INTERVAL) {
                send_heartbeat();
                last_heartbeat = now;
            }

            /* Test: envoyer un message toutes les 10 secondes */
            test_message_counter++;
            if (test_message_counter >= 1000) {  /* ~10 secondes avec sleep de 10ms */
                test_message_counter = 0;

                packet_t msg_pkt;
                pkt_init(&msg_pkt, PKT_MESSAGE);

                payload_message_t msg;
                const char* text = "Hello from client!";
                msg.msg_len = strlen(text);
                memcpy(msg.message, text, msg.msg_len);

                pkt_set_payload(&msg_pkt, &msg, sizeof(uint16_t) + msg.msg_len);
                send_packet(&msg_pkt, 1);
            }
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Cleanup */
    if (client_socket != INVALID_SOCKET_VALUE) {
        /* Envoyer packet de déconnexion */
        packet_t disconnect_pkt;
        pkt_init(&disconnect_pkt, PKT_DISCONNECT);
        payload_disconnect_t disconnect_payload;
        disconnect_payload.reason = 0;
        pkt_set_payload(&disconnect_pkt, &disconnect_payload, sizeof(payload_disconnect_t));
        send_packet(&disconnect_pkt, 0);

        net_close_socket(client_socket);
    }
    net_cleanup();

    printf("\n✓ Client stopped\n");
    return 0;
}

static void handle_packet(packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CHALLENGE: {
            payload_challenge_t ch;
            uint16_t size;
            pkt_get_payload(pkt, &ch, &size);

            printf("→ Received challenge: 0x%08X\n", ch.challenge);
            current_challenge = ch.challenge;
            break;
        }

        case PKT_SESSION_KEY: {
            payload_session_key_t sk;
            uint16_t size;
            pkt_get_payload(pkt, &sk, &size);

            memcpy(session_key, sk.key, SESSION_KEY_SIZE);
            printf("✓ Received session key\n");

            /* Maintenant s'authentifier */
            send_connect();
            break;
        }

        case PKT_ACK: {
            if (!authenticated) {
                printf("✓ Authenticated with server\n");
                authenticated = 1;
                last_heartbeat = time(NULL);
            }
            break;
        }

        case PKT_PONG: {
            printf("← PONG received\n");
            break;
        }

        case PKT_MESSAGE: {
            payload_message_t msg;
            uint16_t size;
            pkt_get_payload(pkt, &msg, &size);

            printf("← Message echoed: \"%.*s\"\n", msg.msg_len, msg.message);
            break;
        }

        case PKT_ERROR: {
            payload_error_t error;
            uint16_t size;
            pkt_get_payload(pkt, &error, &size);

            printf("✗ Error [%d]: %s\n", error.error_code, error.error_msg);
            connected = 0;
            break;
        }

        case PKT_DISCONNECT: {
            printf("← Server requested disconnect\n");
            connected = 0;
            break;
        }

        default:
            printf("← Unknown packet type: %d\n", pkt_get_type(pkt));
            break;
    }
}

static void send_packet(packet_t* pkt, uint8_t encrypt) {
    if (!connected || client_socket == INVALID_SOCKET_VALUE) return;

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
    if (encrypt && authenticated) {
        crypto_encrypt(session_key, pkt->payload, pkt->payload, pkt->header.length);
        pkt_set_flag(pkt, PKT_FLAG_ENCRYPTED);
    }

    /* Sérialiser et envoyer */
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);

    log_packet(LOG_SEND, pkt, "Server");

    net_send(client_socket, buffer, size);
}

static void send_heartbeat(void) {
    printf("→ Sending heartbeat #%u\n", heartbeat_sequence);

    packet_t pkt;
    pkt_init(&pkt, PKT_HEARTBEAT);

    payload_heartbeat_t payload;
    payload.sequence = heartbeat_sequence++;
    payload.challenge_response = crypto_solve_challenge(current_challenge);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 1);
}

static void send_connect(void) {
    printf("→ Requesting authentication\n");

    packet_t pkt;
    pkt_init(&pkt, PKT_CONNECT);

    payload_connect_t payload;
    payload.timestamp = (uint32_t)time(NULL);
    payload.client_id = 1;

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 0);
}
