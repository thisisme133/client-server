#include "network.h"
#include "packet.h"
#include "compression.h"
#include "crc.h"
#include "crypto.h"
#include "logger.h"
#include "pe_loader.h"
#include "blacklist.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <windows.h>
    #include <process.h>
    typedef HANDLE thread_t;
    #define thread_create(thread, func, arg) \
        (*(thread) = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL))
    typedef unsigned int (__stdcall *thread_func_t)(void*);
    #define THREAD_RETURN unsigned int __stdcall
#else
    #include <pthread.h>
    typedef pthread_t thread_t;
    #define thread_create(thread, func, arg) pthread_create(thread, NULL, func, arg)
    typedef void* (*thread_func_t)(void*);
    #define THREAD_RETURN void*
#endif

#define PORT 8888
#define MAX_CLIENTS 32
#define BUFFER_SIZE 2048
#define CHALLENGE_TIMEOUT 5

typedef struct {
    uint8_t active;
    socket_t socket;
    uint8_t authenticated;
    uint8_t session_key[SESSION_KEY_SIZE];
    uint32_t challenge;
    time_t challenge_time;
    char ip_address[46];
    pe_image_t* pe_image;
    uint8_t* mapped_image;
    uint32_t image_size;
} client_info_t;

static client_info_t clients[MAX_CLIENTS];
static socket_t server_socket = INVALID_SOCKET_VALUE;

static void handle_client_packet(uint8_t client_id, packet_t* pkt);
static void send_packet_to_client(uint8_t client_id, packet_t* pkt, uint8_t encrypt);
static THREAD_RETURN client_thread(void* arg);

static void send_challenge(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_CHALLENGE);
    
    payload_challenge_t payload;
    payload.challenge = (uint32_t)rand() * (uint32_t)rand();
    payload.timestamp = (uint32_t)time(NULL);
    
    clients[client_id].challenge = payload.challenge;
    clients[client_id].challenge_time = time(NULL);
    
    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 0);
}

static void send_session_key(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_SESSION_KEY);
    
    payload_session_key_t payload;
    for (int i = 0; i < SESSION_KEY_SIZE; i++) {
        payload.key[i] = rand() % 256;
    }
    
    memcpy(clients[client_id].session_key, payload.key, SESSION_KEY_SIZE);
    
    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 0);
}

static void send_game_list(uint8_t client_id) {
    packet_t pkt;
    pkt_init(&pkt, PKT_GAME_LIST);
    
    payload_game_list_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.count = 1;
    strncpy(payload.games[0], "Counter-Strike 2", 63);
    
    pkt_set_payload(&pkt, &payload, sizeof(payload));
    send_packet_to_client(client_id, &pkt, 1);
}

static void handle_game_select(uint8_t client_id, packet_t* pkt) {
    payload_game_select_t payload;
    uint16_t size;
    pkt_get_payload(pkt, &payload, &size);
    
    /* TODO: Load actual game DLL based on game_id */
    /* For now, use dummy PE data */
    
    /* Send PE in chunks */
    uint32_t chunk_size = 900;
    uint32_t total_chunks = 1;
    
    packet_t chunk_pkt;
    pkt_init(&chunk_pkt, PKT_PE_CHUNK);
    
    payload_pe_chunk_t chunk_payload;
    memset(&chunk_payload, 0, sizeof(chunk_payload));
    chunk_payload.chunk_index = 0;
    chunk_payload.total_chunks = total_chunks;
    chunk_payload.chunk_size = chunk_size;
    chunk_payload.total_size = chunk_size;
    chunk_payload.entry_rva = 0x1000;
    
    /* Fill with dummy data */
    memset(chunk_payload.data, 0x90, chunk_size);
    
    pkt_set_payload(&chunk_pkt, &chunk_payload, 20 + chunk_size);
    send_packet_to_client(client_id, &chunk_pkt, 1);
}

static void handle_client_packet(uint8_t client_id, packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        case PKT_CHALLENGE_RESPONSE: {
            payload_challenge_response_t payload;
            uint16_t size;
            pkt_get_payload(pkt, &payload, &size);
            
            /* Vérifier timeout */
            time_t now = time(NULL);
            if (difftime(now, clients[client_id].challenge_time) > CHALLENGE_TIMEOUT) {
                packet_t err;
                pkt_init(&err, PKT_DISCONNECT);
                send_packet_to_client(client_id, &err, 0);
                clients[client_id].active = 0;
                break;
            }
            
            /* Vérifier la solution */
            uint32_t expected = crypto_solve_challenge(clients[client_id].challenge);
            if (payload.challenge_solution != expected) {
                clients[client_id].active = 0;
                break;
            }
            
            /* Vérifier anti-debug/VM */
            if (payload.is_debugged || payload.is_vm || payload.is_suspended) {
                blacklist_add(clients[client_id].ip_address, 
                             payload.is_debugged ? "Debugger" : 
                             payload.is_vm ? "VM" : "Suspended");
                clients[client_id].active = 0;
                break;
            }
            
            send_session_key(client_id);
            break;
        }
        
        case PKT_CONNECT: {
            if (clients[client_id].authenticated) break;
            
            packet_t ack;
            pkt_init(&ack, PKT_ACK);
            send_packet_to_client(client_id, &ack, 0);
            
            clients[client_id].authenticated = 1;
            send_game_list(client_id);
            break;
        }
        
        case PKT_GAME_SELECT: {
            handle_game_select(client_id, pkt);
            break;
        }
        
        case PKT_PE_COMPLETE: {
            /* Client a terminé l'injection */
            break;
        }
        
        case PKT_DISCONNECT: {
            clients[client_id].active = 0;
            break;
        }
        
        default:
            break;
    }
}

static void send_packet_to_client(uint8_t client_id, packet_t* pkt, uint8_t encrypt) {
    if (!clients[client_id].active) return;
    
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
    
    if (encrypt && clients[client_id].authenticated) {
        crypto_encrypt(clients[client_id].session_key, pkt->payload, 
                      pkt->payload, pkt->header.length);
        pkt_set_flag(pkt, PKT_FLAG_ENCRYPTED);
    }
    
    uint8_t buffer[MAX_PACKET_SIZE];
    uint16_t size = pkt_serialize(pkt, buffer);
    net_send(clients[client_id].socket, buffer, size);
}

static THREAD_RETURN client_thread(void* arg) {
    uint8_t client_id = *(uint8_t*)arg;
    free(arg);
    
    uint8_t buffer[BUFFER_SIZE];
    
    /* Envoyer le challenge initial */
    send_challenge(client_id);
    
    while (clients[client_id].active) {
        int32_t received = net_recv(clients[client_id].socket, buffer, BUFFER_SIZE);
        
        if (received > 0) {
            uint16_t offset = 0;
            while (offset < (uint16_t)received) {
                packet_t pkt;
                uint16_t consumed = pkt_deserialize(&pkt, buffer + offset, received - offset);
                
                if (consumed > 0) {
                    if (pkt_has_flag(&pkt, PKT_FLAG_ENCRYPTED) && clients[client_id].authenticated) {
                        crypto_decrypt(clients[client_id].session_key, pkt.payload, 
                                     pkt.payload, pkt.header.length);
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
                    
                    handle_client_packet(client_id, &pkt);
                    offset += consumed;
                } else {
                    break;
                }
            }
        } else if (received == 0 || !net_would_block()) {
            clients[client_id].active = 0;
            break;
        }
        
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }
    
    net_close_socket(clients[client_id].socket);
    if (clients[client_id].pe_image) {
        free(clients[client_id].pe_image);
    }
    if (clients[client_id].mapped_image) {
        free(clients[client_id].mapped_image);
    }
    clients[client_id].active = 0;
    
    return 0;
}

int main(void) {
    srand((unsigned int)time(NULL));
    
    logger_init();
    blacklist_init();
    
    memset(clients, 0, sizeof(clients));
    
    if (net_init() != 0) {
        return 1;
    }
    
    server_socket = net_create_socket();
    if (server_socket == INVALID_SOCKET_VALUE) {
        net_cleanup();
        return 1;
    }
    
    if (net_bind(server_socket, PORT) != 0) {
        net_close_socket(server_socket);
        net_cleanup();
        return 1;
    }
    
    if (net_listen(server_socket, MAX_CLIENTS) != 0) {
        net_close_socket(server_socket);
        net_cleanup();
        return 1;
    }
    
    while (1) {
        char client_ip[46]; uint16_t client_port;
        socket_t client_socket = net_accept(server_socket, client_ip, &client_port);
        if (client_socket == INVALID_SOCKET_VALUE) {
            continue;
        }
        
        /* Trouver un slot libre */
        uint8_t client_id;
        for (client_id = 0; client_id < MAX_CLIENTS; client_id++) {
            if (!clients[client_id].active) break;
        }
        
        if (client_id >= MAX_CLIENTS) {
            net_close_socket(client_socket);
            continue;
        }
        
        /* Obtenir l'IP du client */
        /* Note: Simplification - on utilise une IP dummy pour l'instant */
        strncpy(clients[client_id].ip_address, client_ip, sizeof(clients[client_id].ip_address) - 1);
        
        /* Vérifier blacklist */
        if (blacklist_is_banned(clients[client_id].ip_address)) {
            net_close_socket(client_socket);
            continue;
        }
        
        clients[client_id].active = 1;
        clients[client_id].socket = client_socket;
        clients[client_id].authenticated = 0;
        
        net_set_nonblocking(client_socket);
        
        uint8_t* arg = malloc(sizeof(uint8_t));
        *arg = client_id;
        
        thread_t thread;
        thread_create(&thread, client_thread, arg);
        
#ifndef _WIN32
        pthread_detach(thread);
#endif
    }
    
    net_close_socket(server_socket);
    net_cleanup();
    blacklist_shutdown();
    
    return 0;
}
