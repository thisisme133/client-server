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
    #include <tlhelp32.h>
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

/* Module list variables */
#define MAX_MODULES 32
static char available_modules[MAX_MODULES][128];
static uint8_t module_count = 0;

/* PE Loading variables */
static uint32_t pe_image_size = 0;
static uint32_t pe_entry_rva = 0;
static uint32_t pe_imports_size = 0;
static uint8_t* pe_imports_buffer = NULL;
static uint32_t pe_imports_received = 0;
static void* pe_allocated_base = NULL;
static uint8_t* pe_image_buffer = NULL;
static uint32_t pe_image_received = 0;
static uint8_t target_is_64bit = 0;

/* Remote process injection variables */
#ifdef _WIN32
static HANDLE target_process_handle = NULL;
static DWORD target_pid = 0;
static char target_process_name[128] = {0};
#endif

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
static void handle_module_list(packet_t* pkt);
static void handle_pe_metadata(packet_t* pkt);
static void handle_pe_imports(packet_t* pkt);
static void handle_pe_image(packet_t* pkt);
static void parse_imports_and_allocate(void);
static void resolve_imports(void);
static void execute_pe(void);
static void send_game_select(uint32_t module_id);

#ifdef _WIN32
/* Process enumeration */
static DWORD find_process_by_name(const char* process_name);
#endif

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
        printf("\n✗ Must be connected and authenticated to load module\n");
        return;
    }

#ifndef _WIN32
    printf("\n✗ Manual mapping is only supported on Windows\n");
    return;
#else
    /* Parser l'argument: module_id process_name */
    uint32_t module_id = 0;
    char process_name[128] = {0};

    if (!args || strlen(args) == 0) {
        printf("\nUsage: load <module_id> <process_name>\n");
        printf("  module_id:    Module identifier (0, 1, 2, ...)\n");
        printf("  process_name: Target process executable name (e.g., notepad.exe)\n");
        printf("\nExample: load 0 notepad.exe\n");
        return;
    }

    if (sscanf(args, "%u %127s", &module_id, process_name) != 2) {
        printf("\n✗ Invalid arguments. Usage: load <module_id> <process_name>\n");
        return;
    }

    if (module_id >= module_count) {
        printf("\n✗ Invalid module ID. Valid range: 0-%u\n", module_count - 1);
        return;
    }

    /* Trouver le processus cible */
    DWORD pid = find_process_by_name(process_name);
    if (pid == 0) {
        printf("\n✗ Process not found: %s\n", process_name);
        printf("   Make sure the process is running\n");
        return;
    }

    /* Ouvrir le processus */
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("\n✗ Failed to open process (PID: %lu)\n", pid);
        printf("   Error code: %lu\n", GetLastError());
        printf("   Try running as Administrator\n");
        return;
    }

    printf("✓ Opened process handle: 0x%p\n", hProcess);

    /* Sauvegarder les informations du processus cible */
    target_process_handle = hProcess;
    target_pid = pid;
    strncpy(target_process_name, process_name, sizeof(target_process_name) - 1);

    /* Envoyer la sélection du module */
    send_game_select(module_id);
#endif
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
    cmd_register("load", "Load and inject a DLL module (args: module_id process_name)", cmd_load);

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

        case PKT_MODULE_LIST: {
            handle_module_list(pkt);
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

#ifdef _WIN32
static DWORD find_process_by_name(const char* process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("✗ Failed to create process snapshot\n");
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD found_pid = 0;
    do {
        if (_stricmp(pe32.szExeFile, process_name) == 0) {
            found_pid = pe32.th32ProcessID;
            printf("✓ Found process: %s (PID: %lu)\n", process_name, found_pid);
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return found_pid;
}
#endif

static void handle_module_list(packet_t* pkt) {
    payload_module_list_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    module_count = payload.count;

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║              Available DLL Modules                         ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");

    for (uint8_t i = 0; i < module_count && i < MAX_MODULES; i++) {
        strncpy(available_modules[i], payload.modules[i], sizeof(available_modules[i]) - 1);
        available_modules[i][sizeof(available_modules[i]) - 1] = '\0';
        printf("║ [%2u] %-54s║\n", i, available_modules[i]);
    }

    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\nUse 'load <module_id>' to inject a module\n");
    printf("Example: load 0\n\n");
}

static void send_game_select(uint32_t module_id) {
    printf("\n→ Requesting module %u\n", module_id);

    packet_t pkt;
    pkt_init(&pkt, PKT_GAME_SELECT);

    payload_game_select_t payload;
    payload.module_id = module_id;

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
    target_is_64bit = payload.is_64bit;

    printf("← PE Metadata received:\n");
    printf("   DLL: %s (%s)\n", payload.dll_name, target_is_64bit ? "x64" : "x86");
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

    /* Allouer la mémoire pour l'image PE dans le processus DISTANT */
#ifdef _WIN32
    if (!target_process_handle) {
        printf("✗ No target process handle\n");
        return;
    }

    /* Allouer dans le processus distant */
    pe_allocated_base = VirtualAllocEx(target_process_handle, NULL, pe_image_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pe_allocated_base) {
        printf("✗ Failed to allocate PE memory in remote process\n");
        printf("   Error code: %lu\n", GetLastError());
        return;
    }

    printf("✓ Allocated %u bytes in remote process at 0x%p\n", pe_image_size, pe_allocated_base);

    /* Allouer un buffer LOCAL pour construire l'image avant de l'envoyer au processus distant */
    pe_image_buffer = (uint8_t*)malloc(pe_image_size);
    if (!pe_image_buffer) {
        printf("✗ Failed to allocate local buffer\n");
        VirtualFreeEx(target_process_handle, pe_allocated_base, 0, MEM_RELEASE);
        return;
    }

    memset(pe_image_buffer, 0, pe_image_size);
    pe_image_received = 0;
#else
    printf("⚠ Manual mapping not supported on this platform\n");
    return;
#endif

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

/* Structure pour passer les données au shellcode de résolution d'imports */
typedef struct {
    /* Fonctions kernel32.dll */
    void* pLoadLibraryA;
    void* pGetProcAddress;

    /* Données */
    void* pImportData;          /* Pointeur vers les données d'import dans le processus distant */
    uint32_t import_data_size;
    void* pImageBase;           /* Base de l'image PE dans le processus distant */
} shellcode_data_t;

static void resolve_imports(void) {
    printf("\n→ Resolving imports in remote process...\n");

#ifdef _WIN32
    if (!target_process_handle) {
        printf("✗ No target process handle\n");
        return;
    }

    /* Obtenir les adresses de LoadLibraryA et GetProcAddress
     * Note: kernel32.dll est chargé à la même adresse dans tous les processus */
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    void* pLoadLibraryA = (void*)GetProcAddress(hKernel32, "LoadLibraryA");
    void* pGetProcAddress = (void*)GetProcAddress(hKernel32, "GetProcAddress");

    printf("   LoadLibraryA:   0x%p\n", pLoadLibraryA);
    printf("   GetProcAddress: 0x%p\n", pGetProcAddress);

    /* Allouer de la mémoire pour les données d'import dans le processus distant */
    void* remote_import_data = VirtualAllocEx(target_process_handle, NULL, pe_imports_size,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_import_data) {
        printf("✗ Failed to allocate import data in remote process\n");
        return;
    }

    /* Écrire les données d'import dans le processus distant */
    SIZE_T bytes_written;
    if (!WriteProcessMemory(target_process_handle, remote_import_data,
                            pe_imports_buffer, pe_imports_size, &bytes_written)) {
        printf("✗ Failed to write import data to remote process\n");
        VirtualFreeEx(target_process_handle, remote_import_data, 0, MEM_RELEASE);
        return;
    }

    printf("✓ Import data written to remote process at 0x%p\n", remote_import_data);

    /* Shellcode pour résoudre les imports dans le processus distant
     * Ce shellcode est en x86-64 et fait:
     * 1. Lire les données de configuration
     * 2. Parser le buffer d'imports
     * 3. Appeler LoadLibraryA pour chaque DLL
     * 4. Appeler GetProcAddress pour chaque fonction
     * 5. Écrire l'adresse dans l'IAT
     * 6. Retourner
     */
    unsigned char shellcode[] = {
        /* Pour simplifier, on va utiliser une approche différente:
         * On va résoudre les imports dans NOTRE processus, puis les écrire directement
         * dans le processus distant via WriteProcessMemory.
         * Ceci est plus simple et plus fiable. */
        0xC3  /* ret - placeholder */
    };

    /* Approche simplifiée: résoudre les imports localement puis écrire dans le processus distant */
    printf("   Resolving imports locally...\n");

    uint32_t offset = 0;
    uint32_t resolved_count = 0;

    while (offset < pe_imports_size) {
        /* Lire le nom du module */
        if (offset + 2 > pe_imports_size) break;
        uint16_t module_name_len;
        memcpy(&module_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        if (offset + module_name_len > pe_imports_size) break;
        char module_name[256];
        memcpy(module_name, pe_imports_buffer + offset, module_name_len);
        module_name[module_name_len] = '\0';
        offset += module_name_len;

        /* Charger le module (dans notre processus pour obtenir l'adresse) */
        HMODULE hModule = LoadLibraryA(module_name);
        if (!hModule) {
            printf("   ✗ Failed to load module: %s\n", module_name);
            /* Skip this import */
            if (offset + 2 > pe_imports_size) break;
            uint16_t fn_len;
            memcpy(&fn_len, pe_imports_buffer + offset, 2);
            offset += 2;
            if (fn_len == 0 && offset + 2 <= pe_imports_size) offset += 2;
            else if (offset + fn_len <= pe_imports_size) offset += fn_len;
            if (offset + 4 <= pe_imports_size) offset += 4;
            continue;
        }

        /* Lire le nom de la fonction ou l'ordinal */
        if (offset + 2 > pe_imports_size) break;
        uint16_t function_name_len;
        memcpy(&function_name_len, pe_imports_buffer + offset, 2);
        offset += 2;

        void* proc_addr = NULL;

        if (function_name_len == 0) {
            /* Import par ordinal */
            if (offset + 2 > pe_imports_size) break;
            uint16_t ordinal;
            memcpy(&ordinal, pe_imports_buffer + offset, 2);
            offset += 2;

            proc_addr = (void*)GetProcAddress(hModule, (LPCSTR)(uintptr_t)ordinal);
        } else {
            /* Import par nom */
            if (offset + function_name_len > pe_imports_size) break;
            char function_name[256];
            memcpy(function_name, pe_imports_buffer + offset, function_name_len);
            function_name[function_name_len] = '\0';
            offset += function_name_len;

            proc_addr = (void*)GetProcAddress(hModule, function_name);
        }

        /* Lire l'IAT RVA */
        if (offset + 4 > pe_imports_size) break;
        uint32_t iat_rva;
        memcpy(&iat_rva, pe_imports_buffer + offset, 4);
        offset += 4;

        /* Écrire l'adresse directement dans le buffer local */
        if (proc_addr && iat_rva < pe_image_size) {
            void** iat_entry = (void**)(pe_image_buffer + iat_rva);
            *iat_entry = proc_addr;
            resolved_count++;
        } else if (!proc_addr) {
            printf("   ✗ Failed to resolve import at offset %u\n", offset);
        }
    }

    printf("✓ Resolved %u imports\n", resolved_count);

    /* Libérer les données d'import temporaires dans le processus distant */
    VirtualFreeEx(target_process_handle, remote_import_data, 0, MEM_RELEASE);

#else
    printf("⚠ Import resolution not supported on this platform\n");
#endif
}

static void execute_pe(void) {
    printf("\n→ Writing PE image to remote process and executing...\n");

#ifdef _WIN32
    if (!target_process_handle) {
        printf("✗ No target process handle\n");
        return;
    }

    /* Écrire l'image PE complète (avec imports résolus) dans le processus distant */
    SIZE_T bytes_written;
    if (!WriteProcessMemory(target_process_handle, pe_allocated_base,
                            pe_image_buffer, pe_image_size, &bytes_written)) {
        printf("✗ Failed to write PE image to remote process\n");
        printf("   Error code: %lu\n", GetLastError());

        /* Envoyer échec au serveur */
        packet_t pkt;
        pkt_init(&pkt, PKT_PE_COMPLETE);
        payload_pe_complete_t payload;
        payload.success = 0;
        payload.thread_id = 0;
        pkt_set_payload(&pkt, &payload, sizeof(payload));
        send_packet(&pkt, 1);
        return;
    }

    printf("✓ PE image written to remote process (%llu bytes)\n", (unsigned long long)bytes_written);

    /* Calculer l'adresse du point d'entrée dans le processus distant */
    void* remote_entry_point = (void*)((uint8_t*)pe_allocated_base + pe_entry_rva);
    printf("✓ Remote entry point: 0x%p\n", remote_entry_point);

    /* Créer un thread DISTANT pour exécuter le PE (DllMain) */
    DWORD thread_id = 0;
    HANDLE hThread = CreateRemoteThread(target_process_handle, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remote_entry_point,
                                        pe_allocated_base,  /* DllMain parameter: HINSTANCE */
                                        0, &thread_id);
    if (hThread) {
        printf("✓ Remote thread created in PID %lu (Thread ID: %lu)\n", target_pid, thread_id);

        /* Attendre un peu pour voir si le thread démarre correctement */
        DWORD wait_result = WaitForSingleObject(hThread, 2000);
        if (wait_result == WAIT_TIMEOUT) {
            printf("✓ Thread is running (timeout after 2s - likely successful)\n");
        } else if (wait_result == WAIT_OBJECT_0) {
            DWORD exit_code;
            GetExitCodeThread(hThread, &exit_code);
            printf("✓ Thread completed with exit code: %lu\n", exit_code);
        }

        /* Envoyer confirmation au serveur */
        packet_t pkt;
        pkt_init(&pkt, PKT_PE_COMPLETE);

        payload_pe_complete_t payload;
        payload.success = 1;
        payload.thread_id = thread_id;

        pkt_set_payload(&pkt, &payload, sizeof(payload));
        send_packet(&pkt, 1);

        printf("✓ PE manual mapping injection completed successfully!\n");
        printf("   Target:  %s (PID: %lu)\n", target_process_name, target_pid);
        printf("   Base:    0x%p\n", pe_allocated_base);
        printf("   Entry:   0x%p\n", remote_entry_point);

        CloseHandle(hThread);
    } else {
        printf("✗ Failed to create remote thread\n");
        printf("   Error code: %lu\n", GetLastError());

        /* Envoyer échec au serveur */
        packet_t pkt;
        pkt_init(&pkt, PKT_PE_COMPLETE);
        payload_pe_complete_t payload;
        payload.success = 0;
        payload.thread_id = 0;
        pkt_set_payload(&pkt, &payload, sizeof(payload));
        send_packet(&pkt, 1);
    }

    /* Fermer le handle du processus */
    if (target_process_handle) {
        CloseHandle(target_process_handle);
        target_process_handle = NULL;
    }

#else
    printf("⚠ PE execution not supported on this platform\n");
#endif

    /* Nettoyer les buffers locaux */
    if (pe_imports_buffer) {
        free(pe_imports_buffer);
        pe_imports_buffer = NULL;
    }
    if (import_table) {
        free(import_table);
        import_table = NULL;
    }
    if (pe_image_buffer) {
        free(pe_image_buffer);
        pe_image_buffer = NULL;
    }
}
