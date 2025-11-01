#include "network.h"
#include "packet.h"
#include "compression.h"
#include "crc.h"
#include "crypto.h"
#include "logger.h"
#include "command.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/time.h>
#endif

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048
#define HEARTBEAT_INTERVAL 5  /* 5 secondes */

static socket_t client_socket = INVALID_SOCKET_VALUE;
static uint8_t connected = 0;
static uint8_t authenticated = 0;
static uint8_t session_key[SESSION_KEY_SIZE];
static uint32_t current_challenge = 0;
static uint32_t heartbeat_sequence = 0;
static time_t last_heartbeat = 0;

/* Variables de contrôle */
static uint8_t heartbeat_enabled = 1;
static uint8_t packet_logging_enabled = 1;
static time_t last_ping_time = 0;
static uint8_t waiting_for_pong = 0;

/* PE Loading variables */
static uint32_t pe_image_size = 0;
static uint32_t pe_entry_rva = 0;
static uint32_t pe_imports_size = 0;
static uint8_t* pe_imports_buffer = NULL;
static uint32_t pe_imports_received = 0;
static void* pe_allocated_base = NULL;
static uint8_t* pe_image_buffer = NULL;
static uint32_t pe_image_received = 0;

/* Import entry structure for parsing */
typedef struct {
    uint32_t iat_rva;
    void* resolved_address;
} import_entry_t;

static import_entry_t* import_table = NULL;
static uint32_t import_count = 0;

/* Prototypes */
static void handle_packet(packet_t* pkt);
static void send_packet(packet_t* pkt, uint8_t encrypt);
static void send_heartbeat(void);
static void send_connect(void);

/* PE Loading handlers */
static void handle_pe_metadata(packet_t* pkt);
static void handle_pe_imports(packet_t* pkt);
static void handle_pe_image(packet_t* pkt);
static void parse_imports_and_allocate(void);
static void resolve_imports(void);
static void execute_pe(void);
static void send_game_select(uint32_t game_id, uint8_t arch);

/* Command handlers */
static void cmd_stop(const char* args);
static void cmd_ping(const char* args);
static void cmd_heartbeat(const char* args);
static void cmd_nolog(const char* args);
static void cmd_status(const char* args);
static void cmd_load(const char* args);

static void cmd_stop(const char* args) {
    (void)args;
    printf("\n✓ Stopping client...\n");
    connected = 0;
}

static void cmd_ping(const char* args) {
    (void)args;
    if (!connected) {
        printf("\n✗ Not connected to server\n");
        return;
    }

    printf("\n→ Sending PING to server...\n");
    packet_t pkt;
    pkt_init(&pkt, PKT_PING);
    send_packet(&pkt, 0);
    last_ping_time = time(NULL);
    waiting_for_pong = 1;
}

static void cmd_heartbeat(const char* args) {
    (void)args;
    heartbeat_enabled = !heartbeat_enabled;
    printf("\n✓ Heartbeat: %s\n", heartbeat_enabled ? "ENABLED" : "DISABLED");
}

static void cmd_nolog(const char* args) {
    (void)args;
    packet_logging_enabled = !packet_logging_enabled;
    printf("\n✓ Packet logging: %s\n", packet_logging_enabled ? "ENABLED" : "DISABLED");
}

static void cmd_status(const char* args) {
    (void)args;
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      Client Status                         ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Connected           : %-36s║\n", connected ? "YES" : "NO");
    printf("║ Authenticated       : %-36s║\n", authenticated ? "YES" : "NO");
    printf("║ Heartbeat           : %-36s║\n", heartbeat_enabled ? "ENABLED" : "DISABLED");
    printf("║ Packet logging      : %-36s║\n", packet_logging_enabled ? "ENABLED" : "DISABLED");
    printf("║ Heartbeat sequence  : %-36u║\n", heartbeat_sequence);
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
}

static void cmd_load(const char* args) {
    if (!connected || !authenticated) {
        printf("\n✗ Must be connected and authenticated to load PE\n");
        return;
    }

    /* Parser les arguments: game_id arch */
    uint32_t game_id = 0;
    uint8_t arch = 0;

    if (!args || strlen(args) == 0) {
        printf("\nUsage: load <game_id> <arch>\n");
        printf("  game_id: Game identifier (number)\n");
        printf("  arch:    0 = x86, 1 = x64\n");
        printf("\nExample: load 1 0   (Load game 1 for x86)\n");
        return;
    }

    if (sscanf(args, "%u %hhu", &game_id, &arch) != 2) {
        printf("\n✗ Invalid arguments. Usage: load <game_id> <arch>\n");
        return;
    }

    if (arch > 1) {
        printf("\n✗ Invalid architecture. Use 0 for x86 or 1 for x64\n");
        return;
    }

    send_game_select(game_id, arch);
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("    TCP Client with Heartbeat Authentication\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    logger_init();

    /* Initialiser système de commandes */
    cmd_init();
    cmd_register("help", "Show this help message", (command_callback_t)cmd_help);
    cmd_register("stop", "Stop the client", cmd_stop);
    cmd_register("ping", "Ping the server", cmd_ping);
    cmd_register("heartbeat", "Toggle heartbeat on/off", cmd_heartbeat);
    cmd_register("nolog", "Toggle packet logging on/off", cmd_nolog);
    cmd_register("status", "Show client status", cmd_status);
    cmd_register("load", "Load and inject a PE file (args: game_id arch)", cmd_load);

    printf("Type 'help' for available commands\n\n");
    printf("> ");
    fflush(stdout);

    /* Initialiser réseau */
    if (net_init() != 0) {
        printf("Error: Failed to initialize network\n");
        return 1;
    }

    /* Créer socket */
    client_socket = net_create_socket();
    if (client_socket == INVALID_SOCKET_VALUE) {
        printf("Error: Failed to create socket\n");
        net_cleanup();
        return 1;
    }

    /* Connecter au serveur */
    printf("→ Connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (net_connect(client_socket, SERVER_IP, SERVER_PORT) != 0) {
        printf("✗ Failed to connect to server\n");
        net_close_socket(client_socket);
        net_cleanup();
        return 1;
    }

    printf("✓ Connected to server\n\n");
    connected = 1;

    /* Configuration non-blocking */
    net_set_nonblocking(client_socket);

    /* Boucle principale */
    uint8_t buffer[BUFFER_SIZE];

    while (connected) {
        /* Vérifier les commandes */
        cmd_poll_stdin();

        /* Recevoir données */
        int32_t received = net_recv(client_socket, buffer, BUFFER_SIZE);

        if (received > 0) {
            /* Traiter tous les packets dans le buffer */
            uint16_t offset = 0;
            while (offset < (uint16_t)received) {
                packet_t pkt;
                uint16_t consumed = pkt_deserialize(&pkt, buffer + offset, received - offset);

                if (consumed > 0) {
                    if (packet_logging_enabled) {
                        log_packet(LOG_RECV, &pkt, "Server");
                    }

                    /* Déchiffrer si nécessaire */
                    if (pkt_has_flag(&pkt, PKT_FLAG_ENCRYPTED) && authenticated) {
                        crypto_decrypt(session_key, pkt.payload, pkt.payload, pkt.header.length);
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

                    handle_packet(&pkt);
                    offset += consumed;
                } else {
                    printf("✗ Invalid packet (CRC fail or malformed)\n");
                    break;
                }
            }
        } else if (received == 0) {
            printf("← Server closed connection\n");
            connected = 0;
            break;
        } else if (!net_would_block()) {
            printf("✗ Connection error\n");
            connected = 0;
            break;
        }

        /* Envoyer heartbeat si nécessaire */
        if (authenticated && heartbeat_enabled) {
            time_t now = time(NULL);
            if (difftime(now, last_heartbeat) >= HEARTBEAT_INTERVAL) {
                send_heartbeat();
                last_heartbeat = now;
            }
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    /* Cleanup */
    if (client_socket != INVALID_SOCKET_VALUE) {
        /* Envoyer packet de déconnexion */
        packet_t disconnect_pkt;
        pkt_init(&disconnect_pkt, PKT_DISCONNECT);
        payload_disconnect_t disconnect_payload;
        disconnect_payload.reason = 0;
        pkt_set_payload(&disconnect_pkt, &disconnect_payload, sizeof(payload_disconnect_t));
        send_packet(&disconnect_pkt, 0);

        net_close_socket(client_socket);
    }
    net_cleanup();

    printf("\n✓ Client stopped\n");
    return 0;
}

static void handle_packet(packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CHALLENGE: {
            payload_challenge_t ch;
            uint16_t size;
            pkt_get_payload(pkt, &ch, &size);

            printf("→ Received challenge: 0x%08X\n", ch.challenge);
            current_challenge = ch.challenge;
            break;
        }

        case PKT_SESSION_KEY: {
            payload_session_key_t sk;
            uint16_t size;
            pkt_get_payload(pkt, &sk, &size);

            memcpy(session_key, sk.key, SESSION_KEY_SIZE);
            printf("✓ Received session key\n");

            /* Maintenant s'authentifier */
            send_connect();
            break;
        }

        case PKT_ACK: {
            if (!authenticated) {
                printf("✓ Authenticated with server\n");
                authenticated = 1;
                last_heartbeat = time(NULL);
            }
            break;
        }

        case PKT_PONG: {
            if (waiting_for_pong) {
                time_t now = time(NULL);
                double rtt = difftime(now, last_ping_time);
                printf("← PONG received (RTT: %.0f ms)\n", rtt * 1000);
                waiting_for_pong = 0;
            } else {
                printf("← PONG received\n");
            }
            break;
        }

        case PKT_ERROR: {
            payload_error_t error;
            uint16_t size;
            pkt_get_payload(pkt, &error, &size);

            printf("✗ Error [%d]: %s\n", error.error_code, error.error_msg);
            connected = 0;
            break;
        }

        case PKT_DISCONNECT: {
            printf("← Server requested disconnect\n");
            connected = 0;
            break;
        }

        case PKT_PE_METADATA: {
            handle_pe_metadata(pkt);
            break;
        }

        case PKT_PE_IMPORTS: {
            handle_pe_imports(pkt);
            break;
        }

        case PKT_PE_IMAGE: {
            handle_pe_image(pkt);
            break;
        }

        default:
            printf("← Unknown packet type: %d\n", pkt_get_type(pkt));
            break;
    }
}

static void send_packet(packet_t* pkt, uint8_t encrypt) {
    if (!connected || client_socket == INVALID_SOCKET_VALUE) return;

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
    if (encrypt && authenticated) {
        crypto_encrypt(session_key, pkt->payload, pkt->payload, pkt->header.length);
        pkt_set_flag(pkt, PKT_FLAG_ENCRYPTED);
    }

    /* Sérialiser et envoyer */
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);

    if (packet_logging_enabled) {
        log_packet(LOG_SEND, pkt, "Server");
    }

    net_send(client_socket, buffer, size);
}

static void send_heartbeat(void) {
    printf("→ Sending heartbeat #%u\n", heartbeat_sequence);

    packet_t pkt;
    pkt_init(&pkt, PKT_HEARTBEAT);

    payload_heartbeat_t payload;
    payload.sequence = heartbeat_sequence++;
    payload.challenge_response = crypto_solve_challenge(current_challenge);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 1);
}

static void send_connect(void) {
    printf("→ Requesting authentication\n");

    packet_t pkt;
    pkt_init(&pkt, PKT_CONNECT);

    payload_connect_t payload;
    payload.timestamp = (uint32_t)time(NULL);
    payload.client_id = 1;

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 0);
}

/* ============================================
   PE Loading Functions
   ============================================ */

static void send_game_select(uint32_t game_id, uint8_t arch) {
    printf("\n→ Requesting game %u (%s)\n", game_id, arch == 0 ? "x86" : "x64");

    packet_t pkt;
    pkt_init(&pkt, PKT_GAME_SELECT);

    payload_game_select_t payload;
    payload.game_id = game_id;
    payload.arch = arch;

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 1);
}

static void handle_pe_metadata(packet_t* pkt) {
    payload_pe_metadata_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    pe_image_size = payload.image_size;
    pe_entry_rva = payload.entry_rva;
    pe_imports_size = payload.imports_size;

    printf("← PE Metadata received:\n");
    printf("   Image size:   %u bytes\n", pe_image_size);
    printf("   Entry RVA:    0x%08X\n", pe_entry_rva);
    printf("   Imports size: %u bytes\n", pe_imports_size);

    /* Allouer le buffer pour les imports */
    pe_imports_buffer = (uint8_t*)malloc(pe_imports_size);
    if (!pe_imports_buffer) {
        printf("✗ Failed to allocate imports buffer\n");
        return;
    }

    pe_imports_received = 0;
    printf("✓ Ready to receive imports...\n");
}

static void handle_pe_imports(packet_t* pkt) {
    payload_pe_imports_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    /* Copier le chunk dans le buffer */
    memcpy(pe_imports_buffer + payload.offset, payload.data, payload.chunk_size);
    pe_imports_received += payload.chunk_size;

    printf("← Import chunk [%u/%u bytes]\n", pe_imports_received, payload.total_size);

    /* Si tous les imports sont reçus, parser et allouer */
    if (pe_imports_received >= payload.total_size) {
        printf("✓ All imports received\n");
        parse_imports_and_allocate();
    }
}

static void parse_imports_and_allocate(void) {
    printf("\n→ Parsing imports...\n");

    /* Compter le nombre d'imports */
    uint32_t offset = 0;
    import_count = 0;

    while (offset < pe_imports_size) {
        uint16_t module_name_len;
        if (offset + 2 > pe_imports_size) break;
        memcpy(&module_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        if (offset + module_name_len > pe_imports_size) break;
        offset += module_name_len;

        uint16_t function_name_len;
        if (offset + 2 > pe_imports_size) break;
        memcpy(&function_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        if (function_name_len == 0) {
            /* Ordinal import */
            if (offset + 2 > pe_imports_size) break;
            offset += 2;  /* ordinal */
        } else {
            if (offset + function_name_len > pe_imports_size) break;
            offset += function_name_len;
        }

        if (offset + 4 > pe_imports_size) break;
        offset += 4;  /* IAT RVA */

        import_count++;
    }

    printf("   Found %u imports\n", import_count);

    /* Allouer la table des imports */
    import_table = (import_entry_t*)malloc(import_count * sizeof(import_entry_t));
    if (!import_table) {
        printf("✗ Failed to allocate import table\n");
        return;
    }

    /* Parser et stocker les RVA */
    offset = 0;
    uint32_t idx = 0;

    while (offset < pe_imports_size && idx < import_count) {
        uint16_t module_name_len;
        memcpy(&module_name_len, pe_imports_buffer + offset, 2);
        offset += 2 + module_name_len;

        uint16_t function_name_len;
        memcpy(&function_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        if (function_name_len == 0) {
            offset += 2;  /* ordinal */
        } else {
            offset += function_name_len;
        }

        uint32_t iat_rva;
        memcpy(&iat_rva, pe_imports_buffer + offset, 4);
        offset += 4;

        import_table[idx].iat_rva = iat_rva;
        import_table[idx].resolved_address = NULL;
        idx++;
    }

    printf("✓ Imports parsed\n");

    /* Allouer la mémoire pour l'image PE */
#ifdef _WIN32
    pe_allocated_base = VirtualAlloc(NULL, pe_image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    /* Sur Linux, on peut utiliser mmap mais pas d'exécution réelle */
    pe_allocated_base = malloc(pe_image_size);
#endif

    if (!pe_allocated_base) {
        printf("✗ Failed to allocate PE memory\n");
        return;
    }

    printf("✓ Allocated %u bytes at 0x%p\n", pe_image_size, pe_allocated_base);

    /* Allouer le buffer pour recevoir l'image */
    pe_image_buffer = (uint8_t*)pe_allocated_base;
    pe_image_received = 0;

    /* Envoyer l'adresse de base au serveur */
    packet_t pkt;
    pkt_init(&pkt, PKT_PE_BASE_ADDR);

    payload_pe_base_addr_t payload;
    payload.base_address = (uint64_t)(uintptr_t)pe_allocated_base;

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 1);

    printf("→ Base address sent to server: 0x%llX\n", (unsigned long long)payload.base_address);
    printf("✓ Ready to receive PE image...\n");
}

static void handle_pe_image(packet_t* pkt) {
    payload_pe_image_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    /* Copier le chunk dans le buffer */
    memcpy(pe_image_buffer + payload.offset, payload.data, payload.chunk_size);
    pe_image_received += payload.chunk_size;

    printf("← Image chunk [%u/%u bytes]\n", pe_image_received, payload.total_size);

    /* Si toute l'image est reçue, résoudre les imports et exécuter */
    if (pe_image_received >= payload.total_size) {
        printf("✓ Full PE image received\n");
        resolve_imports();
        execute_pe();
    }
}

static void resolve_imports(void) {
    printf("\n→ Resolving imports...\n");

#ifdef _WIN32
    /* Parser le buffer d'imports et résoudre */
    uint32_t offset = 0;
    uint32_t idx = 0;

    while (offset < pe_imports_size && idx < import_count) {
        /* Lire le nom du module */
        uint16_t module_name_len;
        memcpy(&module_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        char module_name[256];
        memcpy(module_name, pe_imports_buffer + offset, module_name_len);
        module_name[module_name_len] = '\0';
        offset += module_name_len;

        /* Charger le module */
        HMODULE hModule = LoadLibraryA(module_name);
        if (!hModule) {
            printf("   ✗ Failed to load module: %s\n", module_name);
            offset += 2;  /* function_name_len */
            uint16_t fn_len;
            memcpy(&fn_len, pe_imports_buffer + offset - 2, 2);
            if (fn_len == 0) offset += 2;  /* ordinal */
            else offset += fn_len;
            offset += 4;  /* IAT RVA */
            idx++;
            continue;
        }

        /* Lire le nom de la fonction ou l'ordinal */
        uint16_t function_name_len;
        memcpy(&function_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        void* proc_addr = NULL;

        if (function_name_len == 0) {
            /* Import par ordinal */
            uint16_t ordinal;
            memcpy(&ordinal, pe_imports_buffer + offset, 2);
            offset += 2;

            proc_addr = (void*)GetProcAddress(hModule, (LPCSTR)(uintptr_t)ordinal);
        } else {
            /* Import par nom */
            char function_name[256];
            memcpy(function_name, pe_imports_buffer + offset, function_name_len);
            function_name[function_name_len] = '\0';
            offset += function_name_len;

            proc_addr = (void*)GetProcAddress(hModule, function_name);
        }

        /* Lire l'IAT RVA */
        uint32_t iat_rva;
        memcpy(&iat_rva, pe_imports_buffer + offset, 4);
        offset += 4;

        /* Écrire l'adresse dans l'IAT */
        if (proc_addr) {
            void** iat_entry = (void**)((uint8_t*)pe_allocated_base + iat_rva);
            *iat_entry = proc_addr;
        } else {
            printf("   ✗ Failed to resolve function\n");
        }

        idx++;
    }

    printf("✓ Imports resolved (%u functions)\n", import_count);
#else
    printf("⚠ Import resolution not supported on this platform\n");
#endif
}

static void execute_pe(void) {
    printf("\n→ Executing PE...\n");

#ifdef _WIN32
    /* Calculer l'adresse du point d'entrée */
    void* entry_point = (void*)((uint8_t*)pe_allocated_base + pe_entry_rva);

    printf("✓ Entry point: 0x%p\n", entry_point);

    /* Créer un thread pour exécuter le PE */
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry_point, NULL, 0, NULL);
    if (hThread) {
        DWORD thread_id = GetThreadId(hThread);
        printf("✓ Thread created (ID: %lu)\n", thread_id);

        /* Envoyer confirmation au serveur */
        packet_t pkt;
        pkt_init(&pkt, PKT_PE_COMPLETE);

        payload_pe_complete_t payload;
        payload.success = 1;
        payload.thread_id = thread_id;

        pkt_set_payload(&pkt, &payload, sizeof(payload));
        send_packet(&pkt, 1);

        printf("✓ PE injection completed successfully!\n");

        CloseHandle(hThread);
    } else {
        printf("✗ Failed to create thread\n");
    }
#else
    printf("⚠ PE execution not supported on this platform\n");
#endif

    /* Nettoyer */
    if (pe_imports_buffer) {
        free(pe_imports_buffer);
        pe_imports_buffer = NULL;
    }
    if (import_table) {
        free(import_table);
        import_table = NULL;
    }
}
