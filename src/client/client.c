#include "network.h"
#include "packet.h"
#include "compression.h"
#include "crc.h"
#include "crypto.h"
#include "anti_debug.h"
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
#define CHALLENGE_TIMEOUT 5

static socket_t client_socket = INVALID_SOCKET_VALUE;
static uint8_t connected = 0;
static uint8_t authenticated = 0;
static uint8_t session_key[SESSION_KEY_SIZE];
static uint32_t current_challenge = 0;
static time_t challenge_received_time = 0;

static char available_games[16][64];
static uint8_t game_count = 0;

static uint8_t* pe_buffer = NULL;
static uint32_t pe_size = 0;
static uint32_t pe_received = 0;
static uint32_t pe_entry_rva = 0;
static char target_process_name[64] = {0};

#ifdef _WIN32
static HANDLE target_process_handle = NULL;
static DWORD target_pid = 0;
#endif

static void handle_packet(packet_t* pkt);
static void send_packet(packet_t* pkt, uint8_t encrypt);
static void send_connect(void);
static void send_challenge_response(void);

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

static void inject_pe(void) {
    if (!pe_buffer || pe_size == 0 || strlen(target_process_name) == 0) return;

    DWORD pid = find_process_by_name(target_process_name);
    if (pid == 0) return;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return;

    void* base_addr = VirtualAllocEx(hProcess, (LPVOID)0x7FFF0000, pe_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!base_addr) {
        base_addr = VirtualAllocEx(hProcess, NULL, pe_size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!base_addr) {
        CloseHandle(hProcess);
        return;
    }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, base_addr, pe_buffer, pe_size, &written)) {
        VirtualFreeEx(hProcess, base_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    void* entry = (void*)((uint8_t*)base_addr + pe_entry_rva);
    DWORD thread_id;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)entry,
                                        base_addr, 0, &thread_id);

    packet_t pkt;
    pkt_init(&pkt, PKT_PE_COMPLETE);
    payload_pe_complete_t complete;
    complete.success = (hThread != NULL);
    complete.thread_id = thread_id;
    complete.base_address = (uint64_t)(uintptr_t)base_addr;
    pkt_set_payload(&pkt, &complete, sizeof(complete));
    send_packet(&pkt, 1);

    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);

    free(pe_buffer);
    pe_buffer = NULL;
}
#endif

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

        if (current_challenge != 0 && !authenticated) {
            time_t now = time(NULL);
            if (difftime(now, challenge_received_time) >= CHALLENGE_TIMEOUT) {
                connected = 0;
                break;
            }
        }

#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

    if (client_socket != INVALID_SOCKET_VALUE) {
        net_close_socket(client_socket);
    }
    net_cleanup();

    if (pe_buffer) free(pe_buffer);

    return 0;
}

static void handle_packet(packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CHALLENGE: {
            payload_challenge_t ch;
            uint16_t size;
            pkt_get_payload(pkt, &ch, &size);
            current_challenge = ch.challenge;
            challenge_received_time = time(NULL);
            send_challenge_response();
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
                current_challenge = 0;
            }
            break;
        }

        case PKT_ERROR:
        case PKT_DISCONNECT: {
            connected = 0;
            break;
        }

        case PKT_GAME_LIST: {
            payload_game_list_t payload;
            uint16_t size;
            pkt_get_payload(pkt, &payload, &size);
            game_count = payload.count;
            for (uint8_t i = 0; i < game_count && i < 16; i++) {
                strncpy(available_games[i], payload.games[i], sizeof(available_games[i]) - 1);
            }

            if (game_count > 0) {
                packet_t sel;
                pkt_init(&sel, PKT_GAME_SELECT);
                payload_game_select_t game_sel;
                game_sel.game_id = 0;
                strncpy(game_sel.target_process, "cs2.exe", sizeof(game_sel.target_process) - 1);
                strncpy(target_process_name, "cs2.exe", sizeof(target_process_name) - 1);
                pkt_set_payload(&sel, &game_sel, sizeof(game_sel));
                send_packet(&sel, 1);
            }
            break;
        }

        case PKT_PE_CHUNK: {
            payload_pe_chunk_t payload;
            uint16_t size;
            pkt_get_payload(pkt, &payload, &size);

            if (payload.chunk_index == 0) {
                pe_size = payload.total_size;
                pe_entry_rva = payload.entry_rva;
                pe_buffer = (uint8_t*)malloc(pe_size);
                if (!pe_buffer) {
                    connected = 0;
                    break;
                }
                pe_received = 0;
            }

            if (pe_buffer && pe_received + payload.chunk_size <= pe_size) {
                memcpy(pe_buffer + pe_received, payload.data, payload.chunk_size);
                pe_received += payload.chunk_size;
            }

            if (payload.chunk_index == payload.total_chunks - 1) {
#ifdef _WIN32
                inject_pe();
#endif
            }
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
    uint16_t pkt_size = pkt_serialize(pkt, buffer);
    net_send(client_socket, buffer, pkt_size);
}

static void send_challenge_response(void) {
    packet_t pkt;
    pkt_init(&pkt, PKT_CHALLENGE_RESPONSE);

    payload_challenge_response_t payload;
    payload.challenge_solution = crypto_solve_challenge(current_challenge);
    payload.is_debugged = is_debugger_present();
    payload.is_vm = is_virtual_machine();
    payload.is_suspended = is_process_suspended();

    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet(&pkt, 0);
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
