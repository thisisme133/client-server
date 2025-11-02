#include "blacklist.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    char ip[46];        /* IPv4 ou IPv6 */
    char reason[128];
    time_t timestamp;
} blacklist_entry_t;

static blacklist_entry_t blacklist[MAX_BLACKLISTED_IPS];
static uint32_t blacklist_count = 0;

void blacklist_init(void) {
    blacklist_count = 0;
    memset(blacklist, 0, sizeof(blacklist));

    FILE* f = fopen(BLACKLIST_FILE, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f) && blacklist_count < MAX_BLACKLISTED_IPS) {
        /* Format: IP|REASON|TIMESTAMP */
        char* ip = strtok(line, "|");
        char* reason = strtok(NULL, "|");
        char* timestamp_str = strtok(NULL, "|");

        if (ip && reason && timestamp_str) {
            strncpy(blacklist[blacklist_count].ip, ip, sizeof(blacklist[0].ip) - 1);
            strncpy(blacklist[blacklist_count].reason, reason, sizeof(blacklist[0].reason) - 1);
            blacklist[blacklist_count].timestamp = (time_t)atoll(timestamp_str);
            blacklist_count++;
        }
    }

    fclose(f);
}

uint8_t blacklist_is_banned(const char* ip) {
    for (uint32_t i = 0; i < blacklist_count; i++) {
        if (strcmp(blacklist[i].ip, ip) == 0) {
            return 1;
        }
    }
    return 0;
}

void blacklist_add(const char* ip, const char* reason) {
    /* Vérifier si déjà présent */
    if (blacklist_is_banned(ip)) return;

    if (blacklist_count >= MAX_BLACKLISTED_IPS) return;

    strncpy(blacklist[blacklist_count].ip, ip, sizeof(blacklist[0].ip) - 1);
    strncpy(blacklist[blacklist_count].reason, reason, sizeof(blacklist[0].reason) - 1);
    blacklist[blacklist_count].timestamp = time(NULL);
    blacklist_count++;

    /* Sauvegarder dans le fichier */
    FILE* f = fopen(BLACKLIST_FILE, "a");
    if (f) {
        fprintf(f, "%s|%s|%lld\n", ip, reason, (long long)blacklist[blacklist_count - 1].timestamp);
        fclose(f);
    }
}

void blacklist_shutdown(void) {
    blacklist_count = 0;
}
