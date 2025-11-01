/*
 * Protected Function Server
 *
 * Ce module gère la lecture et l'envoi des fichiers .bytes
 * contenant les fonctions protégées aux clients.
 */

#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/stat.h>
#endif

#define PROTECTED_FUNCTIONS_DIR "protected_functions"
#define MAX_FUNCTION_SIZE 65536  /* 64KB max par fonction */

/*
 * Charge les bytes d'une fonction protégée depuis le fichier .bytes
 */
int load_protected_function(const char* function_name, uint8_t* buffer, uint32_t* size) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.bytes", PROTECTED_FUNCTIONS_DIR, function_name);

    printf("   → Loading protected function: %s\n", function_name);
    printf("     Path: %s\n", path);

    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("   ✗ Function file not found: %s\n", path);
        return -1;
    }

    /* Obtenir la taille du fichier */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > MAX_FUNCTION_SIZE) {
        printf("   ✗ Invalid file size: %ld bytes\n", file_size);
        fclose(f);
        return -1;
    }

    /* Lire les bytes */
    size_t bytes_read = fread(buffer, 1, file_size, f);
    fclose(f);

    if (bytes_read != (size_t)file_size) {
        printf("   ✗ Failed to read complete file (read %zu of %ld bytes)\n",
               bytes_read, file_size);
        return -1;
    }

    *size = (uint32_t)file_size;
    printf("   ✓ Loaded %u bytes for function: %s\n", *size, function_name);

    return 0;
}

/*
 * Construit et envoie une réponse avec les bytes de la fonction
 */
void send_function_response(uint8_t client_id,
                             const char* function_name,
                             const uint8_t* bytes,
                             uint32_t size,
                             uint8_t success,
                             void (*send_func)(uint8_t, packet_t*, uint8_t)) {

    packet_t pkt;
    pkt_init(&pkt, PKT_FUNCTION_RESPONSE);

    payload_function_response_t payload;
    memset(&payload, 0, sizeof(payload));

    strncpy(payload.function_name, function_name, sizeof(payload.function_name) - 1);
    payload.success = success;
    payload.size = size;

    if (success && size > 0) {
        /* Copier les bytes dans le payload */
        uint32_t copy_size = size;
        if (copy_size > sizeof(payload.data)) {
            printf("   ⚠ Function too large, truncating (%u > %zu)\n",
                   size, sizeof(payload.data));
            copy_size = sizeof(payload.data);
        }
        memcpy(payload.data, bytes, copy_size);
    }

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_func(client_id, &pkt, 1);

    if (success) {
        printf("   ✓ Sent function '%s' to client %u (%u bytes)\n",
               function_name, client_id, size);
    } else {
        printf("   ✗ Sent failure response for function '%s' to client %u\n",
               function_name, client_id);
    }
}

/*
 * Gère une requête de fonction protégée d'un client
 */
void handle_function_request(uint8_t client_id,
                              packet_t* pkt,
                              void (*send_func)(uint8_t, packet_t*, uint8_t)) {

    payload_function_request_t request;
    uint16_t size;
    pkt_get_payload(pkt, &request, &size);

    printf("← Client %u requests function: %s\n", client_id, request.function_name);

    /* Charger les bytes de la fonction */
    uint8_t function_bytes[MAX_FUNCTION_SIZE];
    uint32_t function_size = 0;

    int result = load_protected_function(request.function_name,
                                          function_bytes,
                                          &function_size);

    if (result == 0) {
        /* Succès - envoyer les bytes */
        send_function_response(client_id, request.function_name,
                               function_bytes, function_size, 1, send_func);
    } else {
        /* Échec - envoyer réponse d'erreur */
        send_function_response(client_id, request.function_name,
                               NULL, 0, 0, send_func);
    }
}
