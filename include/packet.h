#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

/* Types de packets - utiliser uint8_t pour économiser l'espace */
typedef enum {
    PKT_CONNECT = 0,
    PKT_DISCONNECT = 1,
    PKT_CHALLENGE = 2,
    PKT_CHALLENGE_RESPONSE = 3,
    PKT_SESSION_KEY = 4,
    PKT_ACK = 5,
    PKT_ERROR = 6,
    PKT_GAME_LIST = 7,
    PKT_GAME_SELECT = 8,
    PKT_PE_CHUNK = 9,
    PKT_PE_COMPLETE = 10
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
    uint32_t timestamp;
} payload_challenge_t;

typedef struct __attribute__((packed)) {
    uint32_t challenge_solution;
    uint8_t is_debugged;         /* 1 si debugger détecté */
    uint8_t is_vm;               /* 1 si VM détectée */
    uint8_t is_suspended;        /* 1 si processus suspendu */
} payload_challenge_response_t;

typedef struct __attribute__((packed)) {
    uint8_t key[32];
} payload_session_key_t;

typedef struct __attribute__((packed)) {
    uint8_t count;           /* Nombre de jeux */
    char games[16][64];      /* Liste des jeux */
} payload_game_list_t;

typedef struct __attribute__((packed)) {
    uint32_t game_id;        /* ID du jeu sélectionné */
    char target_process[64]; /* Nom du processus cible (ex: cs2.exe) */
} payload_game_select_t;

typedef struct __attribute__((packed)) {
    uint32_t chunk_index;    /* Index du chunk */
    uint32_t total_chunks;   /* Nombre total de chunks */
    uint32_t chunk_size;     /* Taille de ce chunk */
    uint32_t total_size;     /* Taille totale de l'image */
    uint32_t entry_rva;      /* RVA du point d'entrée (dans le 1er chunk) */
    uint8_t data[MAX_PAYLOAD_SIZE - 20];
} payload_pe_chunk_t;

typedef struct __attribute__((packed)) {
    uint8_t success;         /* 1 si succès, 0 sinon */
    uint32_t thread_id;      /* ID du thread créé */
    uint64_t base_address;   /* Adresse où le PE a été mappé */
} payload_pe_complete_t;

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
