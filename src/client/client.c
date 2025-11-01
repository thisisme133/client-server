#include "network.h"
#include "packet.h"
#include "compression.h"
#include <stdio.h>
#include <string.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048

static socket_t client_socket = INVALID_SOCKET_VALUE;
static uint8_t connected = 0;

/* Forward declarations des handlers */
static void handle_connect_response(void);
static void handle_disconnect_response(void);
static void handle_packet(packet_t* pkt);

/* Handlers spécifiques par type de packet */
static void handle_ack(packet_t* pkt);
static void handle_pong(packet_t* pkt);
static void handle_message(packet_t* pkt);
static void handle_error(packet_t* pkt);

/* Utilitaires */
static void send_packet(packet_t* pkt);
static void send_ping(void);
static void send_message(const char* msg);
static void send_data(const uint8_t* data, uint16_t size);

int main(void) {
    printf("TCP Client - Starting...\n");

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
    printf("Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (net_connect(client_socket, SERVER_IP, SERVER_PORT) != 0) {
        printf("Error: Failed to connect to server\n");
        net_close_socket(client_socket);
        net_cleanup();
        return 1;
    }

    printf("Connected to server!\n");
    connected = 1;
    handle_connect_response();

    /* Configuration non-blocking */
    net_set_nonblocking(client_socket);

    /* Envoyer packet de connexion */
    packet_t connect_pkt;
    pkt_init(&connect_pkt, PKT_CONNECT);
    payload_connect_t connect_payload;
    connect_payload.timestamp = 0;
    connect_payload.client_id = 1;
    pkt_set_payload(&connect_pkt, &connect_payload, sizeof(payload_connect_t));
    send_packet(&connect_pkt);

    /* Boucle principale */
    uint8_t buffer[BUFFER_SIZE];
    uint32_t ping_counter = 0;

    while (connected) {
        /* Recevoir données */
        int32_t received = net_recv(client_socket, buffer, BUFFER_SIZE);

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

                handle_packet(&pkt);
            }
        } else if (received == 0) {
            /* Connexion fermée */
            printf("Server closed connection\n");
            handle_disconnect_response();
            connected = 0;
            break;
        } else if (!net_would_block()) {
            /* Erreur */
            printf("Connection error\n");
            handle_disconnect_response();
            connected = 0;
            break;
        }

        /* Envoyer un ping toutes les 100 itérations */
        ping_counter++;
        if (ping_counter >= 100) {
            ping_counter = 0;
            send_ping();
        }

        /* Test: envoyer un message toutes les 200 itérations */
        static uint32_t msg_counter = 0;
        msg_counter++;
        if (msg_counter >= 200) {
            msg_counter = 0;
            send_message("Hello from client!");
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
        send_packet(&disconnect_pkt);

        net_close_socket(client_socket);
    }
    net_cleanup();

    printf("Client stopped\n");
    return 0;
}

static void handle_connect_response(void) {
    printf("Connection established\n");
}

static void handle_disconnect_response(void) {
    printf("Disconnected from server\n");
}

static void handle_packet(packet_t* pkt) {
    /* Switch case pour router vers les handlers spécifiques */
    switch (pkt_get_type(pkt)) {
        case PKT_ACK:
            handle_ack(pkt);
            break;

        case PKT_PONG:
            handle_pong(pkt);
            break;

        case PKT_MESSAGE:
            handle_message(pkt);
            break;

        case PKT_ERROR:
            handle_error(pkt);
            break;

        case PKT_DISCONNECT:
            printf("Server requested disconnect\n");
            connected = 0;
            break;

        default:
            printf("Unknown packet type: %d\n", pkt_get_type(pkt));
            break;
    }
}

static void handle_ack(packet_t* pkt) {
    (void)pkt;  /* Paramètre non utilisé */
    printf("Received: ACK\n");
}

static void handle_pong(packet_t* pkt) {
    (void)pkt;  /* Paramètre non utilisé */
    printf("Received: PONG\n");
}

static void handle_message(packet_t* pkt) {
    payload_message_t msg;
    uint16_t size;
    pkt_get_payload(pkt, &msg, &size);

    printf("Received: MESSAGE [%.*s]\n", msg.msg_len, msg.message);
}

static void handle_error(packet_t* pkt) {
    payload_error_t error;
    uint16_t size;
    pkt_get_payload(pkt, &error, &size);

    printf("Received: ERROR [%d] %s\n", error.error_code, error.error_msg);
}

static void send_packet(packet_t* pkt) {
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

    /* Sérialiser et envoyer */
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);
    net_send(client_socket, buffer, size);
}

static void send_ping(void) {
    printf("Sending: PING\n");
    packet_t pkt;
    pkt_init(&pkt, PKT_PING);
    send_packet(&pkt);
}

static void send_message(const char* msg) {
    printf("Sending: MESSAGE [%s]\n", msg);

    packet_t pkt;
    pkt_init(&pkt, PKT_MESSAGE);

    payload_message_t payload;
    payload.msg_len = strlen(msg);
    if (payload.msg_len > sizeof(payload.message)) {
        payload.msg_len = sizeof(payload.message);
    }
    memcpy(payload.message, msg, payload.msg_len);

    pkt_set_payload(&pkt, &payload, sizeof(uint16_t) + payload.msg_len);
    send_packet(&pkt);
}

static void send_data(const uint8_t* data, uint16_t size) __attribute__((unused));
static void send_data(const uint8_t* data, uint16_t size) {
    printf("Sending: DATA (%d bytes)\n", size);

    packet_t pkt;
    pkt_init(&pkt, PKT_DATA);

    payload_data_t payload;
    payload.data_len = size;
    if (payload.data_len > sizeof(payload.data)) {
        payload.data_len = sizeof(payload.data);
    }
    memcpy(payload.data, data, payload.data_len);

    pkt_set_payload(&pkt, &payload, sizeof(uint16_t) + payload.data_len);
    send_packet(&pkt);
}
