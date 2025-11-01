#ifndef PROTECTED_FUNCTION_SERVER_H
#define PROTECTED_FUNCTION_SERVER_H

#include "packet.h"
#include <stdint.h>

/*
 * Charge les bytes d'une fonction protégée depuis le fichier .bytes
 *
 * @param function_name Nom de la fonction (ex: "PROTECTED_MyFunction")
 * @param buffer Buffer pour stocker les bytes
 * @param size Pointeur vers la taille (sortie)
 * @return 0 si succès, -1 si erreur
 */
int load_protected_function(const char* function_name, uint8_t* buffer, uint32_t* size);

/*
 * Envoie une réponse avec les bytes de la fonction au client
 *
 * @param client_id ID du client
 * @param function_name Nom de la fonction
 * @param bytes Bytes de la fonction (ou NULL si échec)
 * @param size Taille des bytes
 * @param success 1 si succès, 0 si échec
 * @param send_func Fonction callback pour envoyer le packet
 */
void send_function_response(uint8_t client_id,
                             const char* function_name,
                             const uint8_t* bytes,
                             uint32_t size,
                             uint8_t success,
                             void (*send_func)(uint8_t, packet_t*, uint8_t));

/*
 * Gère une requête de fonction protégée d'un client
 *
 * @param client_id ID du client
 * @param pkt Packet de requête (PKT_FUNCTION_REQUEST)
 * @param send_func Fonction callback pour envoyer la réponse
 */
void handle_function_request(uint8_t client_id,
                              packet_t* pkt,
                              void (*send_func)(uint8_t, packet_t*, uint8_t));

#endif /* PROTECTED_FUNCTION_SERVER_H */
