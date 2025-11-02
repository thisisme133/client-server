#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <stdint.h>

#define BLACKLIST_FILE "blacklist.txt"
#define MAX_BLACKLISTED_IPS 1000

/*
 * Initialise le système de blacklist
 * Charge les IPs depuis le fichier
 */
void blacklist_init(void);

/*
 * Vérifie si une IP est blacklistée
 * @param ip Adresse IP (format string "192.168.1.1")
 * @return 1 si blacklistée, 0 sinon
 */
uint8_t blacklist_is_banned(const char* ip);

/*
 * Ajoute une IP à la blacklist
 * @param ip Adresse IP à bannir
 * @param reason Raison du bannissement
 */
void blacklist_add(const char* ip, const char* reason);

/*
 * Nettoie le système de blacklist
 */
void blacklist_shutdown(void);

#endif /* BLACKLIST_H */
