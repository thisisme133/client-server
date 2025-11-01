#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

/* Types de packets - utiliser uint8_t pour économiser l'espace */
typedef enum {
    PKT_CONNECT = 0,
    PKT_DISCONNECT = 1,
    PKT_PING = 2,
    PKT_PONG = 3,
    PKT_DATA = 4,
    PKT_ACK = 5,
    PKT_ERROR = 6,
    PKT_HEARTBEAT = 7,
    PKT_CHALLENGE = 8,
    PKT_SESSION_KEY = 9,
    PKT_MODULE_LIST = 10,
    PKT_GAME_SELECT = 11,
    PKT_PE_METADATA = 12,
    PKT_PE_IMPORTS = 13,
    PKT_PE_BASE_ADDR = 14,
    PKT_PE_IMAGE = 15,
    PKT_PE_COMPLETE = 16,
    PKT_FUNCTION_REQUEST = 17,
    PKT_FUNCTION_RESPONSE = 18
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
} payload_challenge_t;

typedef struct __attribute__((packed)) {
    uint8_t key[32];
} payload_session_key_t;

/* PE Loading payloads */
typedef struct __attribute__((packed)) {
    uint8_t count;           /* Nombre de modules */
    char modules[32][128];   /* Liste des noms de DLL */
} payload_module_list_t;

typedef struct __attribute__((packed)) {
    uint32_t module_id;      /* Identifiant du module */
} payload_game_select_t;

typedef struct __attribute__((packed)) {
    uint32_t image_size;     /* SizeOfImage */
    uint32_t entry_rva;      /* RVA du point d'entrée */
    uint32_t imports_size;   /* Taille du buffer d'imports */
    uint8_t is_64bit;        /* 1 si PE64, 0 si PE32 */
    char dll_name[128];      /* Nom de la DLL */
} payload_pe_metadata_t;

typedef struct __attribute__((packed)) {
    uint32_t offset;         /* Offset dans le buffer total */
    uint32_t total_size;     /* Taille totale du buffer */
    uint16_t chunk_size;     /* Taille de ce chunk */
    uint8_t data[MAX_PAYLOAD_SIZE - 10];
} payload_pe_imports_t;

typedef struct __attribute__((packed)) {
    uint64_t base_address;   /* Adresse de base allouée */
} payload_pe_base_addr_t;

typedef struct __attribute__((packed)) {
    uint32_t offset;         /* Offset dans l'image totale */
    uint32_t total_size;     /* Taille totale de l'image */
    uint16_t chunk_size;     /* Taille de ce chunk */
    uint8_t data[MAX_PAYLOAD_SIZE - 10];
} payload_pe_image_t;

typedef struct __attribute__((packed)) {
    uint8_t success;         /* 1 si succès, 0 sinon */
    uint32_t thread_id;      /* ID du thread créé */
} payload_pe_complete_t;

/* Protected function request/response */
typedef struct __attribute__((packed)) {
    char function_name[256]; /* Nom de la fonction demandée */
} payload_function_request_t;

typedef struct __attribute__((packed)) {
    char function_name[256]; /* Nom de la fonction */
    uint32_t size;           /* Taille des bytes */
    uint8_t success;         /* 1 si trouvée, 0 sinon */
    uint8_t data[MAX_PAYLOAD_SIZE - 261];  /* Bytes de la fonction */
} payload_function_response_t;

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
