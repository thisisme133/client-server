#include "network.h"
#include "packet.h"
#include "compression.h"
#include "crc.h"
#include "crypto.h"
#include "logger.h"
#include "command.h"
#include "pe_loader.h"
#include "protected_function_server.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
    #include <direct.h>
    #define getcwd _getcwd
    typedef HANDLE thread_t;
    #define thread_create(thread, func, arg) \
        (*(thread) = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL))
    #define thread_join(thread) WaitForSingleObject(thread, INFINITE)
    typedef unsigned int (__stdcall *thread_func_t)(void*);
    #define THREAD_RETURN unsigned int __stdcall
#else
    #include <pthread.h>
    #include <unistd.h>
    typedef pthread_t thread_t;
    #define thread_create(thread, func, arg) pthread_create(thread, NULL, func, arg)
    #define thread_join(thread) pthread_join(thread, NULL)
    typedef void* (*thread_func_t)(void*);
    #define THREAD_RETURN void*
#endif

#define MAX_CLIENTS 32
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048
#define HEARTBEAT_TIMEOUT 10  /* 10 secondes */
#define CHALLENGE_TIMEOUT 5   /* 5 secondes pour répondre au challenge */

typedef struct {
    socket_t socket;
    uint8_t active;
    uint8_t authenticated;
    char ip[16];
    uint16_t port;
    uint32_t current_challenge;
    uint8_t session_key[SESSION_KEY_SIZE];
    time_t last_heartbeat;
    time_t challenge_sent_time;
    thread_t thread;

    /* PE Loading */
    pe_image_t* pe_image;
    pe_import_buffer_t* import_buffer;
    uint64_t client_base_address;
    uint8_t* mapped_image;
    uint32_t selected_module_id;
} client_info_t;

static client_info_t clients[MAX_CLIENTS];
static socket_t server_socket = INVALID_SOCKET_VALUE;

/* Variables globales pour contrôle */
static uint8_t server_running = 1;
static uint8_t packet_logging_enabled = 1;

/* Modules disponibles (DLLs dans games/) */
#define MAX_MODULES 32
static char available_modules[MAX_MODULES][128];
static uint32_t module_count = 0;

/* Fonctions pour la gestion des modules */
static void scan_modules(void);
static void send_module_list(uint8_t client_id);

/* Prototypes */
static THREAD_RETURN client_thread(void* arg);
static void handle_packet(uint8_t client_id, packet_t* pkt);
static void send_packet_to_client(uint8_t client_id, packet_t* pkt, uint8_t encrypt);
static void send_challenge(uint8_t client_id);
static void send_session_key(uint8_t client_id);
static void check_heartbeat_timeout(void);

/* PE Loading handlers */
static void handle_game_select(uint8_t client_id, packet_t* pkt);
static void handle_pe_base_addr(uint8_t client_id, packet_t* pkt);
static void send_pe_metadata(uint8_t client_id);
static void send_pe_imports(uint8_t client_id);
static void send_pe_image(uint8_t client_id);

/* Command handlers */
static void cmd_stop(const char* args);
static void cmd_nolog(const char* args);
static void cmd_stats(const char* args);
static void cmd_list_clients(const char* args);

static void cmd_stop(const char* args) {
    (void)args;
    printf("\n✓ Stopping server...\n");
    server_running = 0;
}

static void cmd_nolog(const char* args) {
    (void)args;
    packet_logging_enabled = !packet_logging_enabled;
    printf("\n✓ Packet logging: %s\n", packet_logging_enabled ? "ENABLED" : "DISABLED");
}

static void cmd_stats(const char* args) {
    (void)args;
    uint8_t active_count = 0;
    uint8_t auth_count = 0;

    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            active_count++;
            if (clients[i].authenticated) auth_count++;
        }
    }

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                     Server Statistics                      ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Active clients      : %-36d║\n", active_count);
    printf("║ Authenticated       : %-36d║\n", auth_count);
    printf("║ Max clients         : %-36d║\n", MAX_CLIENTS);
    printf("║ Packet logging      : %-36s║\n", packet_logging_enabled ? "ENABLED" : "DISABLED");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
}

static void cmd_list_clients(const char* args) {
    (void)args;
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                       Active Clients                       ║\n");
    printf("╠════╦══════════════════════╦═══════╦═════════════════════════╣\n");
    printf("║ ID ║ IP Address           ║ Port  ║ Status                  ║\n");
    printf("╠════╬══════════════════════╬═══════╬═════════════════════════╣\n");

    uint8_t found = 0;
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            printf("║ %-2d ║ %-20s ║ %-5d ║ %-23s ║\n",
                   i, clients[i].ip, clients[i].port,
                   clients[i].authenticated ? "Authenticated" : "Not authenticated");
            found = 1;
        }
    }

    if (!found) {
        printf("║              No active clients                             ║\n");
    }

    printf("╚════╩══════════════════════╩═══════╩═════════════════════════╝\n\n");
}

/* ============================================
   Module Management Functions
   ============================================ */

#ifdef _WIN32
static void scan_modules(void) {
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile("games\\*.dll", &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("✗ No DLLs found in games/\n");
        return;
    }

    module_count = 0;
    do {
        if (module_count >= MAX_MODULES) {
            printf("⚠ Too many DLLs, max %d\n", MAX_MODULES);
            break;
        }

        strncpy(available_modules[module_count], findData.cFileName,
                sizeof(available_modules[module_count]) - 1);
        printf("  [%u] %s\n", module_count, findData.cFileName);
        module_count++;
    } while (FindNextFile(hFind, &findData) != 0);

    FindClose(hFind);
}
#else
#include <dirent.h>
static void scan_modules(void) {
    DIR* dir = opendir("games");
    if (!dir) {
        printf("✗ Cannot open games/ directory\n");
        return;
    }

    struct dirent* entry;
    module_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (module_count >= MAX_MODULES) {
            printf("⚠ Too many DLLs, max %d\n", MAX_MODULES);
            break;
        }

        const char* ext = strrchr(entry->d_name, '.');
        if (ext && (strcmp(ext, ".dll") == 0 || strcmp(ext, ".so") == 0)) {
            strncpy(available_modules[module_count], entry->d_name,
                    sizeof(available_modules[module_count]) - 1);
            printf("  [%u] %s\n", module_count, entry->d_name);
            module_count++;
        }
    }

    closedir(dir);
}
#endif

static void send_module_list(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_MODULE_LIST);

    payload_module_list_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.count = module_count;

    for (uint32_t i = 0; i < module_count && i < 32; i++) {
        strncpy(payload.modules[i], available_modules[i], 127);
    }

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 1);

    printf("✓ Client %d: Module list sent (%u modules)\n", client_id, module_count);
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("    TCP Multi-threaded Server with Authentication\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    logger_init();

    /* Scanner les DLLs disponibles */
    printf("Scanning games/ for DLLs...\n");
    scan_modules();
    printf("✓ Found %u DLL(s)\n\n", module_count);

    /* Initialiser système de commandes */
    cmd_init();
    cmd_register("help", "Show this help message", (command_callback_t)cmd_help);
    cmd_register("stop", "Stop the server", cmd_stop);
    cmd_register("nolog", "Toggle packet logging on/off", cmd_nolog);
    cmd_register("stats", "Show server statistics", cmd_stats);
    cmd_register("clients", "List active clients", cmd_list_clients);

    printf("Type 'help' for available commands\n\n");
    printf("> ");
    fflush(stdout);

    /* Initialiser réseau */
    if (net_init() != 0) {
        printf("Error: Failed to initialize network\n");
        return 1;
    }

    /* Créer socket */
    server_socket = net_create_socket();
    if (server_socket == INVALID_SOCKET_VALUE) {
        printf("Error: Failed to create socket\n");
        net_cleanup();
        return 1;
    }

    /* Configuration socket */
    net_set_reuse_addr(server_socket);

    /* Bind */
    if (net_bind(server_socket, SERVER_PORT) != 0) {
        printf("Error: Failed to bind to port %d\n", SERVER_PORT);
        net_close_socket(server_socket);
        net_cleanup();
        return 1;
    }

    /* Listen */
    if (net_listen(server_socket, 10) != 0) {
        printf("Error: Failed to listen\n");
        net_close_socket(server_socket);
        net_cleanup();
        return 1;
    }

    printf("✓ Server listening on port %d\n\n", SERVER_PORT);

    /* Initialiser clients */
    memset(clients, 0, sizeof(clients));
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = INVALID_SOCKET_VALUE;
    }

    /* Boucle principale d'acceptation */
    while (server_running) {
        /* Vérifier les commandes */
        cmd_poll_stdin();

        /* Accepter nouvelle connexion */
        char ip[16];
        uint16_t port;
        socket_t new_socket = net_accept(server_socket, ip, &port);

        if (new_socket != INVALID_SOCKET_VALUE) {
            /* Trouver un slot libre */
            int8_t slot = -1;
            for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
                if (!clients[i].active) {
                    slot = i;
                    break;
                }
            }

            if (slot >= 0) {
                clients[slot].socket = new_socket;
                clients[slot].active = 1;
                clients[slot].authenticated = 0;
                strncpy(clients[slot].ip, ip, 16);
                clients[slot].port = port;
                clients[slot].last_heartbeat = time(NULL);
                clients[slot].challenge_sent_time = 0;

                /* Générer challenge et clé de session */
                clients[slot].current_challenge = crypto_generate_challenge();
                crypto_generate_session_key(clients[slot].session_key, SESSION_KEY_SIZE);

                printf("✓ Client %d connected from %s:%d\n", slot, ip, port);

                /* Créer thread pour ce client */
                thread_create(&clients[slot].thread, client_thread, (void*)(intptr_t)slot);
            } else {
                printf("✗ Max clients reached, rejecting connection\n");
                net_close_socket(new_socket);
            }
        }

        /* Vérifier les timeouts heartbeat */
        check_heartbeat_timeout();

#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }

    /* Cleanup */
    net_close_socket(server_socket);
    net_cleanup();
    return 0;
}

static THREAD_RETURN client_thread(void* arg) {
    uint8_t client_id = (uint8_t)(intptr_t)arg;
    uint8_t buffer[BUFFER_SIZE];

    printf("→ Thread started for client %d\n", client_id);

    /* Petit délai pour laisser le client se préparer */
#ifdef _WIN32
    Sleep(100);
#else
    usleep(100000);
#endif

    /* Envoyer challenge */
    send_challenge(client_id);

    /* Petit délai entre les deux packets */
#ifdef _WIN32
    Sleep(50);
#else
    usleep(50000);
#endif

    /* Envoyer clé de session */
    send_session_key(client_id);

    /* Boucle de réception */
    while (clients[client_id].active) {
        int32_t received = net_recv(clients[client_id].socket, buffer, BUFFER_SIZE);

        if (received > 0) {
            /* Traiter tous les packets dans le buffer */
            uint16_t offset = 0;
            while (offset < (uint16_t)received) {
                packet_t pkt;
                uint16_t consumed = pkt_deserialize(&pkt, buffer + offset, received - offset);

                if (consumed > 0) {
                    char peer_info[32];
                    if (packet_logging_enabled) {
                        snprintf(peer_info, sizeof(peer_info), "%s:%d",
                                 clients[client_id].ip, clients[client_id].port);
                        log_packet(LOG_RECV, &pkt, peer_info);
                    }

                    /* Déchiffrer si nécessaire */
                    if (pkt_has_flag(&pkt, PKT_FLAG_ENCRYPTED) && clients[client_id].authenticated) {
                        crypto_decrypt(clients[client_id].session_key,
                                     pkt.payload, pkt.payload, pkt.header.length);
                        pkt.header.flags &= ~PKT_FLAG_ENCRYPTED;
                    }

                    /* Décompresser si nécessaire */
                    if (pkt_has_flag(&pkt, PKT_FLAG_COMPRESSED)) {
                        uint8_t decompressed[MAX_PAYLOAD_SIZE];
                        uint16_t decompressed_size = decompress_data(
                            pkt.payload, pkt.header.length,
                            decompressed, MAX_PAYLOAD_SIZE);
                        memcpy(pkt.payload, decompressed, decompressed_size);
                        pkt.header.length = decompressed_size;
                        pkt.header.flags &= ~PKT_FLAG_COMPRESSED;
                    }

                    handle_packet(client_id, &pkt);
                    offset += consumed;
                } else {
                    printf("✗ Client %d: Invalid packet (CRC fail or malformed)\n", client_id);
                    break;
                }
            }
        } else if (received == 0) {
            printf("← Client %d disconnected\n", client_id);
            break;
        } else if (!net_would_block()) {
            printf("✗ Client %d: Connection error\n", client_id);
            break;
        }

        /* Vérifier timeout du challenge (5 secondes) */
        if (clients[client_id].challenge_sent_time > 0) {
            time_t now = time(NULL);
            if (difftime(now, clients[client_id].challenge_sent_time) > CHALLENGE_TIMEOUT) {
                printf("✗ Client %d: Challenge timeout (no response in 5s) - disconnecting silently\n", client_id);
                break;
            }
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Cleanup */
    net_close_socket(clients[client_id].socket);
    clients[client_id].active = 0;
    clients[client_id].socket = INVALID_SOCKET_VALUE;

    printf("✓ Thread stopped for client %d\n", client_id);

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void handle_packet(uint8_t client_id, packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CONNECT: {
            /* Client demande authentification (déjà envoyé challenge/key) */
            clients[client_id].authenticated = 1;
            packet_t ack;
            pkt_init(&ack, PKT_ACK);
            send_packet_to_client(client_id, &ack, 0);

            /* Envoyer la liste des modules disponibles */
            send_module_list(client_id);
            break;
        }

        case PKT_HEARTBEAT: {
            payload_heartbeat_t hb;
            uint16_t size;
            pkt_get_payload(pkt, &hb, &size);

            /* Vérifier la réponse au challenge */
            uint32_t expected = crypto_solve_challenge(clients[client_id].current_challenge);

            if (hb.challenge_response == expected) {
                clients[client_id].last_heartbeat = time(NULL);
                clients[client_id].challenge_sent_time = 0;  /* Réinitialiser le timeout */

                /* Envoyer nouveau challenge */
                clients[client_id].current_challenge = crypto_generate_challenge();
                send_challenge(client_id);
            } else {
                printf("✗ Client %d: Invalid heartbeat response\n", client_id);
                packet_t err;
                pkt_init(&err, PKT_ERROR);
                payload_error_t payload;
                payload.error_code = 1;
                strncpy(payload.error_msg, "Invalid heartbeat challenge", 127);
                pkt_set_payload(&err, &payload, sizeof(payload));
                send_packet_to_client(client_id, &err, 0);
            }
            break;
        }

        case PKT_PING: {
            packet_t pong;
            pkt_init(&pong, PKT_PONG);
            send_packet_to_client(client_id, &pong, 1);
            break;
        }

        case PKT_DISCONNECT: {
            printf("Client %d requested disconnect\n", client_id);
            clients[client_id].active = 0;
            break;
        }

        case PKT_GAME_SELECT: {
            handle_game_select(client_id, pkt);
            break;
        }

        case PKT_PE_BASE_ADDR: {
            handle_pe_base_addr(client_id, pkt);
            break;
        }

        case PKT_FUNCTION_REQUEST: {
            handle_function_request(client_id, pkt, send_packet_to_client);
            break;
        }

        default:
            printf("Client %d: Unknown packet type %d\n", client_id, pkt_get_type(pkt));
            break;
    }
}

static void send_packet_to_client(uint8_t client_id, packet_t* pkt, uint8_t encrypt) {
    if (!clients[client_id].active) return;

    /* Compresser si bénéfique */
    if (should_compress(pkt->payload, pkt->header.length)) {
        uint8_t compressed[MAX_PAYLOAD_SIZE];
        uint16_t compressed_size = compress_data(
            pkt->payload, pkt->header.length,
            compressed, MAX_PAYLOAD_SIZE);

        if (compressed_size < pkt->header.length) {
            memcpy(pkt->payload, compressed, compressed_size);
            pkt->header.length = compressed_size;
            pkt_set_flag(pkt, PKT_FLAG_COMPRESSED);
        }
    }

    /* Chiffrer si demandé et authentifié */
    if (encrypt && clients[client_id].authenticated) {
        crypto_encrypt(clients[client_id].session_key,
                      pkt->payload, pkt->payload, pkt->header.length);
        pkt_set_flag(pkt, PKT_FLAG_ENCRYPTED);
    }

    /* Sérialiser et envoyer */
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);

    if (packet_logging_enabled) {
        char peer_info[32];
        snprintf(peer_info, sizeof(peer_info), "%s:%d",
                 clients[client_id].ip, clients[client_id].port);
        log_packet(LOG_SEND, pkt, peer_info);
    }

    net_send(clients[client_id].socket, buffer, size);
}

static void send_challenge(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_CHALLENGE);

    payload_challenge_t payload;
    payload.challenge = clients[client_id].current_challenge;

    pkt_set_payload(&pkt, &payload, sizeof(payload));

    /* Enregistrer le moment où le challenge est envoyé */
    clients[client_id].challenge_sent_time = time(NULL);

    send_packet_to_client(client_id, &pkt, 0);
}

static void send_session_key(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_SESSION_KEY);

    payload_session_key_t payload;
    memcpy(payload.key, clients[client_id].session_key, SESSION_KEY_SIZE);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 0);
}

static void check_heartbeat_timeout(void) {
    time_t now = time(NULL);

    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].authenticated) {
            if (difftime(now, clients[i].last_heartbeat) > HEARTBEAT_TIMEOUT) {
                printf("✗ Client %d: Heartbeat timeout\n", i);
                clients[i].active = 0;
            }
        }
    }
}

/* ============================================
   PE Loading Functions
   ============================================ */

static void handle_game_select(uint8_t client_id, packet_t* pkt) {
    payload_game_select_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    printf("→ Client %d: Module select - ID=%u\n", client_id, payload.module_id);

    /* Vérifier que le module_id est valide */
    if (payload.module_id >= module_count) {
        printf("✗ Client %d: Invalid module ID %u (max: %u)\n",
               client_id, payload.module_id, module_count - 1);
        return;
    }

    const char* dll_name = available_modules[payload.module_id];
    char dll_path[256];
    snprintf(dll_path, sizeof(dll_path), "games/%s", dll_name);

    printf("   DLL: %s\n", dll_name);

    /* Stocker le module_id */
    clients[client_id].selected_module_id = payload.module_id;

    /* Allouer et charger le PE */
    clients[client_id].pe_image = (pe_image_t*)malloc(sizeof(pe_image_t));
    if (!clients[client_id].pe_image) {
        printf("✗ Client %d: Failed to allocate PE image\n", client_id);
        return;
    }

    if (pe_load_file(dll_path, clients[client_id].pe_image) != 0) {
        printf("✗ Client %d: Failed to load DLL: %s\n", client_id, dll_path);
        free(clients[client_id].pe_image);
        clients[client_id].pe_image = NULL;
        return;
    }

    printf("✓ Client %d: PE loaded - Size=%u, Entry=0x%X\n",
           client_id,
           clients[client_id].pe_image->image_size,
           clients[client_id].pe_image->entry_rva);

    /* Construire le buffer d'imports */
    clients[client_id].import_buffer = (pe_import_buffer_t*)malloc(sizeof(pe_import_buffer_t));
    if (!clients[client_id].import_buffer) {
        printf("✗ Client %d: Failed to allocate import buffer\n", client_id);
        pe_free(clients[client_id].pe_image);
        free(clients[client_id].pe_image);
        clients[client_id].pe_image = NULL;
        return;
    }

    if (pe_build_import_buffer(clients[client_id].pe_image, clients[client_id].import_buffer) != 0) {
        printf("✗ Client %d: Failed to build import buffer\n", client_id);
        free(clients[client_id].import_buffer);
        pe_free(clients[client_id].pe_image);
        free(clients[client_id].pe_image);
        clients[client_id].pe_image = NULL;
        clients[client_id].import_buffer = NULL;
        return;
    }

    printf("✓ Client %d: Import buffer built - Size=%u bytes\n",
           client_id, clients[client_id].import_buffer->size);

    /* Envoyer les métadonnées */
    send_pe_metadata(client_id);

    /* Envoyer le buffer d'imports */
    send_pe_imports(client_id);
}

static void send_pe_metadata(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_PE_METADATA);

    payload_pe_metadata_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.image_size = clients[client_id].pe_image->image_size;
    payload.entry_rva = clients[client_id].pe_image->entry_rva;
    payload.imports_size = clients[client_id].import_buffer->size;
    payload.is_64bit = clients[client_id].pe_image->is_64bit;

    const char* dll_name = available_modules[clients[client_id].selected_module_id];
    strncpy(payload.dll_name, dll_name, sizeof(payload.dll_name) - 1);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 1);

    printf("✓ Client %d: PE metadata sent (%s, %s)\n",
           client_id, dll_name, payload.is_64bit ? "x64" : "x86");
}

static void send_pe_imports(uint8_t client_id) {
    pe_import_buffer_t* imp_buf = clients[client_id].import_buffer;
    uint32_t total_size = imp_buf->size;
    uint32_t offset = 0;

    /* Calculer la taille max d'un chunk */
    uint16_t max_chunk = MAX_PAYLOAD_SIZE - 10;  /* 10 bytes pour les métadonnées du chunk */

    while (offset < total_size) {
        packet_t pkt;
        pkt_init(&pkt, PKT_PE_IMPORTS);

        payload_pe_imports_t payload;
        payload.offset = offset;
        payload.total_size = total_size;
        payload.chunk_size = (total_size - offset) > max_chunk ? max_chunk : (total_size - offset);

        memcpy(payload.data, imp_buf->buffer + offset, payload.chunk_size);

        pkt_set_payload(&pkt, &payload, 10 + payload.chunk_size);
        send_packet_to_client(client_id, &pkt, 1);

        offset += payload.chunk_size;

        printf("→ Client %d: Import chunk sent [%u/%u bytes]\n",
               client_id, offset, total_size);

        /* Petit délai entre les chunks */
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    printf("✓ Client %d: All imports sent (%u bytes)\n", client_id, total_size);
}

static void handle_pe_base_addr(uint8_t client_id, packet_t* pkt) {
    payload_pe_base_addr_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    clients[client_id].client_base_address = payload.base_address;

    printf("→ Client %d: Base address received - 0x%llX\n",
           client_id, (unsigned long long)payload.base_address);

    /* Allouer le buffer pour l'image mappée */
    uint32_t image_size = clients[client_id].pe_image->image_size;
    clients[client_id].mapped_image = (uint8_t*)malloc(image_size);
    if (!clients[client_id].mapped_image) {
        printf("✗ Client %d: Failed to allocate mapped image buffer\n", client_id);
        return;
    }

    /* Mapper les sections */
    if (pe_map_sections(clients[client_id].pe_image, clients[client_id].mapped_image) != 0) {
        printf("✗ Client %d: Failed to map sections\n", client_id);
        free(clients[client_id].mapped_image);
        clients[client_id].mapped_image = NULL;
        return;
    }

    printf("✓ Client %d: Sections mapped\n", client_id);

    /* Appliquer les relocations */
    if (pe_apply_relocations(clients[client_id].pe_image,
                             clients[client_id].mapped_image,
                             payload.base_address) != 0) {
        printf("✗ Client %d: Failed to apply relocations\n", client_id);
        free(clients[client_id].mapped_image);
        clients[client_id].mapped_image = NULL;
        return;
    }

    printf("✓ Client %d: Relocations applied\n", client_id);

    /* Envoyer l'image finale */
    send_pe_image(client_id);

    /* Nettoyer les ressources serveur */
    pe_free(clients[client_id].pe_image);
    free(clients[client_id].pe_image);
    clients[client_id].pe_image = NULL;

    pe_free_import_buffer(clients[client_id].import_buffer);
    free(clients[client_id].import_buffer);
    clients[client_id].import_buffer = NULL;

    free(clients[client_id].mapped_image);
    clients[client_id].mapped_image = NULL;
}

static void send_pe_image(uint8_t client_id) {
    uint32_t total_size = clients[client_id].pe_image->image_size;
    uint32_t offset = 0;

    /* Calculer la taille max d'un chunk */
    uint16_t max_chunk = MAX_PAYLOAD_SIZE - 10;

    while (offset < total_size) {
        packet_t pkt;
        pkt_init(&pkt, PKT_PE_IMAGE);

        payload_pe_image_t payload;
        payload.offset = offset;
        payload.total_size = total_size;
        payload.chunk_size = (total_size - offset) > max_chunk ? max_chunk : (total_size - offset);

        memcpy(payload.data, clients[client_id].mapped_image + offset, payload.chunk_size);

        pkt_set_payload(&pkt, &payload, 10 + payload.chunk_size);
        send_packet_to_client(client_id, &pkt, 1);

        offset += payload.chunk_size;

        printf("→ Client %d: Image chunk sent [%u/%u bytes]\n",
               client_id, offset, total_size);

        /* Petit délai entre les chunks */
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    printf("✓ Client %d: Full PE image sent (%u bytes)\n", client_id, total_size);
}
