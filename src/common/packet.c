#include "packet.h"
#include "crc.h"
#include <string.h>

void pkt_init(packet_t* pkt, uint8_t type) {
    memset(pkt, 0, sizeof(packet_t));
    pkt->header.type = type;
    pkt->header.flags = 0;
    pkt->header.length = 0;
    pkt->header.crc = 0;
}

void pkt_set_payload(packet_t* pkt, const void* data, uint16_t size) {
    if (size > MAX_PAYLOAD_SIZE) {
        size = MAX_PAYLOAD_SIZE;
    }
    memcpy(pkt->payload, data, size);
    pkt->header.length = size;
}

void pkt_get_payload(const packet_t* pkt, void* data, uint16_t* size) {
    uint16_t len = pkt->header.length;
    if (len > MAX_PAYLOAD_SIZE) {
        len = MAX_PAYLOAD_SIZE;
    }
    memcpy(data, pkt->payload, len);
    if (size) *size = len;
}

uint16_t pkt_serialize(packet_t* pkt, uint8_t* buffer) {
    /* Calculer CRC sur header (sans CRC) + payload */
    uint8_t crc_buffer[MAX_PACKET_SIZE];
    uint16_t crc_size = sizeof(packet_header_t) - sizeof(uint32_t) + pkt->header.length;

    memcpy(crc_buffer, &pkt->header, sizeof(packet_header_t) - sizeof(uint32_t));
    if (pkt->header.length > 0) {
        memcpy(crc_buffer + sizeof(packet_header_t) - sizeof(uint32_t),
               pkt->payload, pkt->header.length);
    }

    /* Calculer et stocker le CRC dans le paquet original */
    pkt->header.crc = crc32_calculate(crc_buffer, crc_size);

    /* Copier dans le buffer de sortie */
    uint16_t total_size = sizeof(packet_header_t) + pkt->header.length;
    memcpy(buffer, &pkt->header, sizeof(packet_header_t));

    if (pkt->header.length > 0) {
        memcpy(buffer + sizeof(packet_header_t), pkt->payload, pkt->header.length);
    }

    return total_size;
}

uint16_t pkt_deserialize(packet_t* pkt, const uint8_t* buffer, uint16_t buffer_size) {
    if (buffer_size < sizeof(packet_header_t)) {
        return 0;
    }

    /* Lire header */
    memcpy(&pkt->header, buffer, sizeof(packet_header_t));

    /* Vérifier la taille */
    if (pkt->header.length > MAX_PAYLOAD_SIZE) {
        return 0;
    }

    uint16_t total_size = sizeof(packet_header_t) + pkt->header.length;
    if (buffer_size < total_size) {
        return 0;
    }

    /* Lire payload */
    if (pkt->header.length > 0) {
        memcpy(pkt->payload, buffer + sizeof(packet_header_t), pkt->header.length);
    }

    /* Vérifier CRC */
    uint8_t crc_buffer[MAX_PACKET_SIZE];
    uint16_t crc_size = sizeof(packet_header_t) - sizeof(uint32_t) + pkt->header.length;

    memcpy(crc_buffer, &pkt->header, sizeof(packet_header_t) - sizeof(uint32_t));
    if (pkt->header.length > 0) {
        memcpy(crc_buffer + sizeof(packet_header_t) - sizeof(uint32_t),
               pkt->payload, pkt->header.length);
    }

    if (!crc32_verify(crc_buffer, crc_size, pkt->header.crc)) {
        return 0;  /* CRC invalide */
    }

    return total_size;
}

uint8_t pkt_get_type(const packet_t* pkt) {
    return pkt->header.type;
}

uint16_t pkt_get_length(const packet_t* pkt) {
    return pkt->header.length;
}

uint8_t pkt_has_flag(const packet_t* pkt, uint8_t flag) {
    return (pkt->header.flags & flag) != 0;
}

void pkt_set_flag(packet_t* pkt, uint8_t flag) {
    pkt->header.flags |= flag;
}
