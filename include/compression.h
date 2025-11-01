#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <stdint.h>

/*
 * Compression RLE (Run-Length Encoding) simple et efficace
 * Format: [count][byte] où count indique le nombre de répétitions
 */

/* Compresser les données (retourne la taille compressée) */
uint16_t compress_data(const uint8_t* input, uint16_t input_size,
                       uint8_t* output, uint16_t output_max_size);

/* Décompresser les données (retourne la taille décompressée) */
uint16_t decompress_data(const uint8_t* input, uint16_t input_size,
                        uint8_t* output, uint16_t output_max_size);

/* Estimer si la compression est bénéfique */
uint8_t should_compress(const uint8_t* data, uint16_t size);

#endif
