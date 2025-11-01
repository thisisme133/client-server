#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

/* Types de packets - utiliser uint8_t pour économiser l'espace */
typedef enum {
    PKT_CONNECT = 0,
    PKT_DISCONNECT = 1,
    PKT_PING = 2,
    PKT_PONG = 3,
    PKT_MESSAGE = 4,
    PKT_DATA = 5,
    PKT_ACK = 6,
    PKT_ERROR = 7,
    PKT_HEARTBEAT = 8,
    PKT_CHALLENGE = 9,
    PKT_SESSION_KEY = 10
} packet_type_t;

/* Header de packet avec CRC - 8 bytes total */
typedef struct __attribute__((packed)) {
    uint8_t type;        /* Type de packet */
    uint8_t flags;       /* Flags (compressed, encrypted, etc.) */
    uint16_t length;     /* Longueur des données */
    uint32_t crc;        /* CRC32 pour intégrité */
} packet_header_t;

/* Taille maximale d'un packet */
#define MAX_PACKET_SIZE 1024
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(packet_header_t))

/* Flags de packet */
#define PKT_FLAG_COMPRESSED (1 << 0)
#define PKT_FLAG_ENCRYPTED  (1 << 1)

/* Structure de packet complète */
typedef struct {
    packet_header_t header;
    uint8_t payload[MAX_PAYLOAD_SIZE];
} packet_t;

/* Structures de payload spécifiques (compactes) */
typedef struct __attribute__((packed)) {
    uint32_t timestamp;
    uint8_t client_id;
} payload_connect_t;

typedef struct __attribute__((packed)) {
    uint8_t reason;
} payload_disconnect_t;

typedef struct __attribute__((packed)) {
    uint16_t msg_len;
    char message[MAX_PAYLOAD_SIZE - 2];
} payload_message_t;

typedef struct __attribute__((packed)) {
    uint16_t data_len;
    uint8_t data[MAX_PAYLOAD_SIZE - 2];
} payload_data_t;

typedef struct __attribute__((packed)) {
    uint8_t error_code;
    char error_msg[127];
} payload_error_t;

typedef struct __attribute__((packed)) {
    uint32_t sequence;
    uint32_t challenge_response;
} payload_heartbeat_t;

typedef struct __attribute__((packed)) {
    uint32_t challenge;
} payload_challenge_t;

typedef struct __attribute__((packed)) {
    uint8_t key[32];
} payload_session_key_t;

/* Fonctions de création de packets */
void pkt_init(packet_t* pkt, uint8_t type);
void pkt_set_payload(packet_t* pkt, const void* data, uint16_t size);
void pkt_get_payload(const packet_t* pkt, void* data, uint16_t* size);

/* Serialization/Deserialization */
uint16_t pkt_serialize(packet_t* pkt, uint8_t* buffer);
uint16_t pkt_deserialize(packet_t* pkt, const uint8_t* buffer, uint16_t buffer_size);

/* Utilitaires */
uint8_t pkt_get_type(const packet_t* pkt);
uint16_t pkt_get_length(const packet_t* pkt);
uint8_t pkt_has_flag(const packet_t* pkt, uint8_t flag);
void pkt_set_flag(packet_t* pkt, uint8_t flag);

#endif
