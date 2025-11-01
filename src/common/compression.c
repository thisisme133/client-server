#include "compression.h"

uint16_t compress_data(const uint8_t* input, uint16_t input_size,
                       uint8_t* output, uint16_t output_max_size) {
    uint16_t in_pos = 0, out_pos = 0;

    while (in_pos < input_size && out_pos + 1 < output_max_size) {
        uint8_t current = input[in_pos];
        uint8_t count = 1;

        /* Compter les répétitions (max 255) */
        while (in_pos + count < input_size &&
               input[in_pos + count] == current &&
               count < 255) {
            count++;
        }

        /* Si répétition > 3, utiliser RLE, sinon copier directement */
        if (count >= 3) {
            /* Format RLE: 0xFF [count] [byte] */
            if (out_pos + 3 <= output_max_size) {
                output[out_pos++] = 0xFF;  /* Marqueur RLE */
                output[out_pos++] = count;
                output[out_pos++] = current;
                in_pos += count;
            } else {
                break;
            }
        } else {
            /* Copier directement (échapper 0xFF) */
            if (current == 0xFF) {
                if (out_pos + 2 <= output_max_size) {
                    output[out_pos++] = 0xFF;
                    output[out_pos++] = 0x01;  /* 1 répétition de 0xFF */
                    output[out_pos++] = 0xFF;
                    in_pos++;
                } else {
                    break;
                }
            } else {
                output[out_pos++] = current;
                in_pos++;
            }
        }
    }

    return out_pos;
}

uint16_t decompress_data(const uint8_t* input, uint16_t input_size,
                        uint8_t* output, uint16_t output_max_size) {
    uint16_t in_pos = 0, out_pos = 0;

    while (in_pos < input_size && out_pos < output_max_size) {
        if (input[in_pos] == 0xFF) {
            /* Marqueur RLE détecté */
            if (in_pos + 2 >= input_size) break;

            uint8_t count = input[in_pos + 1];
            uint8_t value = input[in_pos + 2];

            /* Décompresser */
            for (uint8_t i = 0; i < count && out_pos < output_max_size; i++) {
                output[out_pos++] = value;
            }

            in_pos += 3;
        } else {
            /* Copier directement */
            output[out_pos++] = input[in_pos++];
        }
    }

    return out_pos;
}

uint8_t should_compress(const uint8_t* data, uint16_t size) {
    if (size < 16) return 0;  /* Trop petit pour être compressé efficacement */

    /* Compter les répétitions */
    uint16_t repeats = 0;
    for (uint16_t i = 1; i < size; i++) {
        if (data[i] == data[i - 1]) {
            repeats++;
        }
    }

    /* Si plus de 20% de répétitions, compresser */
    return (repeats * 5 > size);
}
