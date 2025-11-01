#include "crypto.h"
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

static uint8_t rng_initialized = 0;

static void init_rng(void) {
    if (!rng_initialized) {
#ifdef _WIN32
        srand((uint32_t)GetTickCount());
#else
        struct timeval tv;
        gettimeofday(&tv, NULL);
        srand((uint32_t)(tv.tv_sec * 1000000 + tv.tv_usec));
#endif
        rng_initialized = 1;
    }
}

void crypto_generate_session_key(uint8_t* key, uint16_t size) {
    init_rng();

    for (uint16_t i = 0; i < size; i++) {
        key[i] = (uint8_t)(rand() & 0xFF);
    }
}

void crypto_encrypt(const uint8_t* key, const uint8_t* input, uint8_t* output, uint16_t size) {
    /* Chiffrement XOR avec rotation de clé */
    for (uint16_t i = 0; i < size; i++) {
        output[i] = input[i] ^ key[i % SESSION_KEY_SIZE];
    }
}

void crypto_decrypt(const uint8_t* key, const uint8_t* input, uint8_t* output, uint16_t size) {
    /* XOR est symétrique */
    crypto_encrypt(key, input, output, size);
}

uint32_t crypto_generate_challenge(void) {
    init_rng();

    uint32_t challenge = 0;
    for (uint8_t i = 0; i < 4; i++) {
        challenge = (challenge << 8) | (rand() & 0xFF);
    }

    return challenge;
}

uint32_t crypto_solve_challenge(uint32_t challenge) {
    /*
     * Transformation simple mais non-triviale du challenge
     * Utilise plusieurs opérations pour rendre difficile la prédiction
     */
    uint32_t result = challenge;

    /* Rotation et XOR */
    result = ((result << 13) | (result >> 19)) ^ 0x5A827999;

    /* Multiplication par un nombre premier */
    result = result * 0x01000193;

    /* Rotation inverse */
    result = ((result << 7) | (result >> 25)) ^ 0x9E3779B9;

    /* XOR avec le challenge original */
    result ^= challenge;

    return result;
}
