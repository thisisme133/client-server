#ifndef COMMAND_H
#define COMMAND_H

#include <stdint.h>

/* Type de callback pour les commandes */
typedef void (*command_callback_t)(const char* args);

/* Structure de commande */
typedef struct {
    const char* name;
    const char* description;
    command_callback_t callback;
} command_t;

/* Système de commandes */
#define MAX_COMMANDS 32

/* Initialisation */
void cmd_init(void);

/* Enregistrer une commande */
void cmd_register(const char* name, const char* description, command_callback_t callback);

/* Exécuter une commande */
void cmd_execute(const char* input);

/* Afficher l'aide */
void cmd_help(void);

/* Lire et exécuter des commandes depuis stdin (non-bloquant) */
void cmd_poll_stdin(void);

#endif
