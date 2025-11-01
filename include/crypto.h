#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#define SESSION_KEY_SIZE 32

/* Génération de clé de session */
void crypto_generate_session_key(uint8_t* key, uint16_t size);

/* Chiffrement XOR avec clé de session */
void crypto_encrypt(const uint8_t* key, const uint8_t* input, uint8_t* output, uint16_t size);

/* Déchiffrement XOR avec clé de session (identique au chiffrement) */
void crypto_decrypt(const uint8_t* key, const uint8_t* input, uint8_t* output, uint16_t size);

/* Génération de challenge aléatoire */
uint32_t crypto_generate_challenge(void);

/* Résolution du challenge (simple hash/transformation) */
uint32_t crypto_solve_challenge(uint32_t challenge);

#endif
