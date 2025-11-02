#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <stdint.h>

/*
 * Vérifications anti-debug et anti-VM
 * Ces fonctions détectent si le processus est en cours de debugging,
 * tourne dans une VM, ou est suspendu.
 */

#ifdef _WIN32

/* Vérifie si un debugger est attaché */
uint8_t is_debugger_present(void);

/* Vérifie si on tourne dans une VM */
uint8_t is_virtual_machine(void);

/* Vérifie si le processus est suspendu */
uint8_t is_process_suspended(void);

#else

/* Stubs pour les plateformes non-Windows */
static inline uint8_t is_debugger_present(void) { return 0; }
static inline uint8_t is_virtual_machine(void) { return 0; }
static inline uint8_t is_process_suspended(void) { return 0; }

#endif

#endif /* ANTI_DEBUG_H */
