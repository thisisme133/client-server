#ifndef CRC_H
#define CRC_H

#include <stdint.h>

/* CRC32 pour la vérification d'intégrité des paquets */

/* Calculer le CRC32 des données */
uint32_t crc32_calculate(const uint8_t* data, uint16_t length);

/* Vérifier le CRC32 */
uint8_t crc32_verify(const uint8_t* data, uint16_t length, uint32_t expected_crc);

#endif
