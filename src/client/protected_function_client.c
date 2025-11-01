/*
 * Protected Function Client
 *
 * Ce module gère la restauration et l'exécution des fonctions protégées
 * côté client. Quand une fonction NOPée est appelée, ce système:
 * 1. Demande les bytes au serveur
 * 2. Restaure temporairement la fonction
 * 3. L'exécute
 * 4. La re-NOP après exécution
 */

#ifdef _WIN32

#include "protected_function.h"
#include "packet.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_PROTECTED_FUNCTIONS 64

/* Table des fonctions protégées */
static protected_function_info_t protected_functions[MAX_PROTECTED_FUNCTIONS];
static uint32_t protected_function_count = 0;

/* Variables pour la communication */
static uint8_t waiting_for_function = 0;
static char requested_function_name[256] = {0};
static uint8_t* received_function_bytes = NULL;
static uint32_t received_function_size = 0;
static uint8_t function_request_completed = 0;

/* Callback pour envoyer des packets (sera fourni par le client principal) */
static void (*g_send_packet_callback)(packet_t*, uint8_t) = NULL;

/*
 * Initialise le système de fonctions protégées
 */
int protected_function_init(void) {
    memset(protected_functions, 0, sizeof(protected_functions));
    protected_function_count = 0;
    waiting_for_function = 0;
    function_request_completed = 0;
    received_function_bytes = NULL;
    received_function_size = 0;

    printf("✓ Protected function system initialized\n");
    return 0;
}

/*
 * Nettoie le système de fonctions protégées
 */
void protected_function_shutdown(void) {
    for (uint32_t i = 0; i < protected_function_count; i++) {
        if (protected_functions[i].original_bytes) {
            free(protected_functions[i].original_bytes);
            protected_functions[i].original_bytes = NULL;
        }
    }

    if (received_function_bytes) {
        free(received_function_bytes);
        received_function_bytes = NULL;
    }

    protected_function_count = 0;
    printf("✓ Protected function system shut down\n");
}

/*
 * Définit le callback pour envoyer des packets
 */
void protected_function_set_send_callback(void (*callback)(packet_t*, uint8_t)) {
    g_send_packet_callback = callback;
}

/*
 * Enregistre une fonction protégée
 */
int protected_function_register(const char* name, void* address, uint32_t size) {
    if (protected_function_count >= MAX_PROTECTED_FUNCTIONS) {
        printf("✗ Too many protected functions\n");
        return -1;
    }

    protected_function_info_t* info = &protected_functions[protected_function_count];
    info->name = name;
    info->address = address;
    info->size = size;
    info->original_bytes = NULL;
    info->is_active = 0;

    protected_function_count++;
    printf("✓ Registered protected function: %s at 0x%p (%u bytes)\n",
           name, address, size);

    return 0;
}

/*
 * Demande une fonction au serveur
 */
static void request_function_from_server(const char* function_name) {
    if (!g_send_packet_callback) {
        printf("✗ Send packet callback not set\n");
        return;
    }

    printf("→ Requesting function from server: %s\n", function_name);

    packet_t pkt;
    pkt_init(&pkt, PKT_FUNCTION_REQUEST);

    payload_function_request_t payload;
    memset(&payload, 0, sizeof(payload));
    strncpy(payload.function_name, function_name, sizeof(payload.function_name) - 1);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    g_send_packet_callback(&pkt, 1);

    strncpy(requested_function_name, function_name, sizeof(requested_function_name) - 1);
    waiting_for_function = 1;
    function_request_completed = 0;
}

/*
 * Gère la réception d'une réponse de fonction du serveur
 */
void protected_function_handle_response(packet_t* pkt) {
    payload_function_response_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    printf("← Received function response: %s (%s)\n",
           payload.function_name,
           payload.success ? "success" : "failed");

    if (strcmp(payload.function_name, requested_function_name) != 0) {
        printf("  ⚠ Response for different function (expected: %s)\n",
               requested_function_name);
        return;
    }

    if (!payload.success) {
        printf("  ✗ Server failed to load function\n");
        function_request_completed = 1;
        waiting_for_function = 0;
        return;
    }

    /* Copier les bytes reçus */
    if (received_function_bytes) {
        free(received_function_bytes);
    }

    received_function_bytes = (uint8_t*)malloc(payload.size);
    if (!received_function_bytes) {
        printf("  ✗ Failed to allocate memory for function bytes\n");
        function_request_completed = 1;
        waiting_for_function = 0;
        return;
    }

    memcpy(received_function_bytes, payload.data, payload.size);
    received_function_size = payload.size;

    printf("  ✓ Received %u bytes for function: %s\n",
           payload.size, payload.function_name);

    function_request_completed = 1;
    waiting_for_function = 0;
}

/*
 * Restaure temporairement une fonction avec ses bytes originaux
 */
static int restore_function(void* address, const uint8_t* bytes, uint32_t size) {
    DWORD old_protect;

    /* Changer la protection mémoire */
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("  ✗ Failed to change memory protection (Error: %lu)\n", GetLastError());
        return -1;
    }

    /* Écrire les bytes originaux */
    memcpy(address, bytes, size);

    /* Restaurer la protection (optionnel, on va re-NOPer de toute façon) */
    VirtualProtect(address, size, old_protect, &old_protect);

    printf("  ✓ Function restored (%u bytes written)\n", size);
    return 0;
}

/*
 * Re-NOP une fonction après exécution
 */
static int nop_function(void* address, uint32_t size) {
    DWORD old_protect;

    /* Changer la protection mémoire */
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("  ✗ Failed to change memory protection (Error: %lu)\n", GetLastError());
        return -1;
    }

    /* Écrire des NOPs */
    memset(address, 0x90, size);

    /* Restaurer la protection */
    VirtualProtect(address, size, old_protect, &old_protect);

    printf("  ✓ Function NOPed (%u bytes)\n", size);
    return 0;
}

/*
 * Point d'entrée pour appeler une fonction protégée
 * Cette fonction doit être appelée par un hook/wrapper
 */
void* protected_call_request(const char* function_name, void* return_address) {
    (void)return_address;  /* Peut être utilisé pour le retour */

    printf("\n→ Protected function call: %s\n", function_name);

    /* Trouver l'info de la fonction */
    protected_function_info_t* func_info = NULL;
    for (uint32_t i = 0; i < protected_function_count; i++) {
        if (strcmp(protected_functions[i].name, function_name) == 0) {
            func_info = &protected_functions[i];
            break;
        }
    }

    if (!func_info) {
        printf("  ✗ Function not registered: %s\n", function_name);
        return NULL;
    }

    /* Demander la fonction au serveur */
    request_function_from_server(function_name);

    /* Attendre la réponse (boucle d'attente simple) */
    printf("  ⏳ Waiting for function bytes from server...\n");
    int timeout = 5000;  /* 5 secondes */
    while (waiting_for_function && timeout > 0) {
        Sleep(10);
        timeout -= 10;
    }

    if (!function_request_completed || !received_function_bytes) {
        printf("  ✗ Timeout waiting for function bytes\n");
        return NULL;
    }

    /* Restaurer la fonction */
    if (restore_function(func_info->address, received_function_bytes, received_function_size) != 0) {
        printf("  ✗ Failed to restore function\n");
        return NULL;
    }

    func_info->is_active = 1;

    printf("  ✓ Function ready to execute at 0x%p\n", func_info->address);

    /* Retourner l'adresse de la fonction pour que l'appelant puisse l'exécuter */
    return func_info->address;
}

/*
 * Nettoie après l'exécution d'une fonction protégée
 */
void protected_call_cleanup(const char* function_name) {
    printf("\n→ Cleaning up protected function: %s\n", function_name);

    /* Trouver l'info de la fonction */
    protected_function_info_t* func_info = NULL;
    for (uint32_t i = 0; i < protected_function_count; i++) {
        if (strcmp(protected_functions[i].name, function_name) == 0) {
            func_info = &protected_functions[i];
            break;
        }
    }

    if (!func_info || !func_info->is_active) {
        printf("  ⚠ Function not active or not found\n");
        return;
    }

    /* Re-NOPer la fonction */
    nop_function(func_info->address, func_info->size);

    func_info->is_active = 0;

    /* Libérer les bytes reçus */
    if (received_function_bytes) {
        free(received_function_bytes);
        received_function_bytes = NULL;
        received_function_size = 0;
    }

    printf("  ✓ Function cleaned up and re-NOPed\n");
}

#else

/* Stub pour les plateformes non-Windows */
#include "protected_function.h"

int protected_function_init(void) { return 0; }
void protected_function_shutdown(void) {}

#endif
