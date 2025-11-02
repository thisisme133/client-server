#include "logger.h"
#include "crc.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

/* Symboles pour l'arborescence */
#define SYM_VERTICAL   "│"
#define SYM_BRANCH     "├──"
#define SYM_LAST       "└──"
#define SYM_SPACE      "    "
#define SYM_INDENT     "│   "

/* Couleurs ANSI */
#define COLOR_RESET    "\033[0m"
#define COLOR_SEND     "\033[1;32m"  /* Vert pour envoi */
#define COLOR_RECV     "\033[1;34m"  /* Bleu pour réception */
#define COLOR_HEADER   "\033[1;33m"  /* Jaune pour headers */
#define COLOR_FIELD    "\033[0;36m"  /* Cyan pour champs */
#define COLOR_ERROR    "\033[1;31m"  /* Rouge pour erreurs */
#define COLOR_CRC_OK   "\033[1;32m"  /* Vert pour CRC OK */
#define COLOR_CRC_FAIL "\033[1;31m"  /* Rouge pour CRC fail */

static uint8_t use_colors = 1;

void logger_init(void) {
    /* Détection si terminal supporte les couleurs (simplifié) */
    use_colors = 1;
}

static const char* get_packet_type_name(uint8_t type) {
    switch (type) {
        case PKT_CONNECT: return "CONNECT";
        case PKT_DISCONNECT: return "DISCONNECT";
        case PKT_CHALLENGE: return "CHALLENGE";
        case PKT_CHALLENGE_RESPONSE: return "CHALLENGE_RESPONSE";
        case PKT_SESSION_KEY: return "SESSION_KEY";
        case PKT_ACK: return "ACK";
        case PKT_ERROR: return "ERROR";
        case PKT_GAME_LIST: return "GAME_LIST";
        case PKT_GAME_SELECT: return "GAME_SELECT";
        case PKT_PE_CHUNK: return "PE_CHUNK";
        case PKT_PE_COMPLETE: return "PE_COMPLETE";
        default: return "UNKNOWN";
    }
}

static void get_timestamp(char* buffer, uint16_t size) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buffer, size, "%H:%M:%S", tm_info);
}

void log_header(const char* symbol, const char* format, ...) {
    char timestamp[16];
    get_timestamp(timestamp, sizeof(timestamp));

    printf("\n%s[%s]%s %s ",
           use_colors ? COLOR_HEADER : "",
           timestamp,
           use_colors ? COLOR_RESET : "",
           symbol);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}

void log_field(uint8_t level, const char* name, const char* format, ...) {
    /* Indentation selon le niveau */
    for (uint8_t i = 0; i < level; i++) {
        if (i == level - 1) {
            printf("%s ", SYM_BRANCH);
        } else {
            printf("%s", SYM_INDENT);
        }
    }

    /* Nom du champ */
    printf("%s%s:%s ",
           use_colors ? COLOR_FIELD : "",
           name,
           use_colors ? COLOR_RESET : "");

    /* Valeur */
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
}

void log_separator(void) {
    printf("%s", use_colors ? COLOR_HEADER : "");
    for (uint8_t i = 0; i < 60; i++) printf("─");
    printf("%s\n", use_colors ? COLOR_RESET : "");
}

void log_hex_dump(uint8_t level, const uint8_t* data, uint16_t size) {
    if (size == 0) return;

    uint16_t max_display = 64; /* Limiter l'affichage */
    if (size > max_display) size = max_display;

    for (uint8_t i = 0; i < level; i++) {
        printf("%s", (i == level - 1) ? SYM_BRANCH : SYM_INDENT);
    }
    printf("Hex: ");

    for (uint16_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < size) {
            printf("\n");
            for (uint8_t j = 0; j < level; j++) {
                printf("%s", (j == level - 1) ? SYM_INDENT : SYM_INDENT);
            }
            printf("     ");
        }
    }
    if (size == max_display) printf("...");
    printf("\n");
}

void log_packet(log_direction_t direction, const packet_t* pkt, const char* peer_info) {
    const char* dir_symbol = (direction == LOG_SEND) ? "▲" : "▼";
    const char* dir_color = (direction == LOG_SEND) ? COLOR_SEND : COLOR_RECV;
    const char* dir_text = (direction == LOG_SEND) ? "SEND" : "RECV";

    /* Header principal */
    log_header(dir_symbol, "%s%s%s %s %s[%s]%s",
               use_colors ? dir_color : "",
               dir_text,
               use_colors ? COLOR_RESET : "",
               use_colors ? SYM_VERTICAL : "|",
               use_colors ? COLOR_HEADER : "",
               get_packet_type_name(pkt->header.type),
               use_colors ? COLOR_RESET : "");

    /* Informations peer */
    if (peer_info) {
        log_field(1, "Peer", "%s", peer_info);
    }

    /* Taille totale */
    uint16_t total_size = sizeof(packet_header_t) + pkt->header.length;
    log_field(1, "Total Size", "%u bytes", total_size);

    /* En-tête du paquet */
    log_field(1, "Header", "");
    log_field(2, "Type", "0x%02X (%s)", pkt->header.type, get_packet_type_name(pkt->header.type));
    log_field(2, "Flags", "0x%02X", pkt->header.flags);

    /* Détails des flags */
    if (pkt->header.flags) {
        char flags_str[64] = "";
        if (pkt->header.flags & PKT_FLAG_COMPRESSED) strcat(flags_str, "COMPRESSED ");
        if (pkt->header.flags & PKT_FLAG_ENCRYPTED) strcat(flags_str, "ENCRYPTED ");
        log_field(3, "Active Flags", "%s", flags_str);
    }

    log_field(2, "Payload Length", "%u bytes", pkt->header.length);

    /* CRC */
    uint8_t crc_buffer[MAX_PACKET_SIZE];
    uint16_t crc_size = sizeof(packet_header_t) - sizeof(uint32_t) + pkt->header.length;
    memcpy(crc_buffer, &pkt->header, sizeof(packet_header_t) - sizeof(uint32_t));
    if (pkt->header.length > 0) {
        memcpy(crc_buffer + sizeof(packet_header_t) - sizeof(uint32_t),
               pkt->payload, pkt->header.length);
    }

    uint32_t calculated_crc = crc32_calculate(crc_buffer, crc_size);
    uint8_t crc_valid = (calculated_crc == pkt->header.crc);

    log_field(2, "CRC32", "%s0x%08X%s %s(%s)%s",
              use_colors ? (crc_valid ? COLOR_CRC_OK : COLOR_CRC_FAIL) : "",
              pkt->header.crc,
              use_colors ? COLOR_RESET : "",
              use_colors ? (crc_valid ? COLOR_CRC_OK : COLOR_CRC_FAIL) : "",
              crc_valid ? "VALID" : "INVALID",
              use_colors ? COLOR_RESET : "");

    /* Payload */
    if (pkt->header.length > 0) {
        log_field(1, "Payload", "%u bytes", pkt->header.length);

        /* Décoder selon le type */
        switch (pkt->header.type) {
            case PKT_CHALLENGE: {
                payload_challenge_t ch;
                uint16_t size;
                pkt_get_payload(pkt, &ch, &size);
                log_field(2, "Challenge Value", "0x%08X", ch.challenge);
                break;
            }

            case PKT_SESSION_KEY: {
                payload_session_key_t sk;
                uint16_t size;
                pkt_get_payload(pkt, &sk, &size);
                log_field(2, "Key Size", "%u bytes", sizeof(sk.key));
                log_hex_dump(2, sk.key, sizeof(sk.key));
                break;
            }

            case PKT_ERROR: {
                payload_error_t err;
                uint16_t size;
                pkt_get_payload(pkt, &err, &size);
                log_field(2, "Error Code", "%u", err.error_code);
                log_field(2, "Error Message", "\"%s\"", err.error_msg);
                break;
            }

            default:
                log_hex_dump(2, pkt->payload, pkt->header.length > 64 ? 64 : pkt->header.length);
                break;
        }
    }

    log_separator();
}
