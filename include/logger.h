#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include "packet.h"

/* Système de logging hiérarchique pour les paquets */

/* Types de log */
typedef enum {
    LOG_SEND,
    LOG_RECV
} log_direction_t;

/* Initialiser le logger */
void logger_init(void);

/* Logger un packet complet avec arborescence */
void log_packet(log_direction_t direction, const packet_t* pkt, const char* peer_info);

/* Fonctions auxiliaires pour logging hiérarchique */
void log_header(const char* symbol, const char* format, ...);
void log_field(uint8_t level, const char* name, const char* format, ...);
void log_separator(void);

/* Afficher les données hexadécimales */
void log_hex_dump(uint8_t level, const uint8_t* data, uint16_t size);

#endif
