#ifndef PROTECTED_FUNCTION_H
#define PROTECTED_FUNCTION_H

#include <stdint.h>

/*
 * Système de protection de fonctions
 *
 * Les fonctions marquées avec PROTECTED_FUNCTION seront:
 * 1. Placées dans une section spéciale ".protect"
 * 2. Leurs noms seront préfixés avec "PROTECTED_"
 * 3. Un outil de patching les trouvera via le PDB
 * 4. Elles seront NOPées et sauvegardées en .bytes
 * 5. Au runtime, elles seront demandées au serveur à l'exécution
 */

#ifdef _WIN32
    /* Attribut pour placer la fonction dans la section .protect */
    #define PROTECTED_FUNCTION __declspec(code_seg(".protect")) __declspec(noinline)

    /* Macro pour forcer un préfixe dans le nom du symbole */
    #define PROTECTED_NAME(name) PROTECTED_##name
#else
    /* Sur Linux, pas de protection pour l'instant */
    #define PROTECTED_FUNCTION
    #define PROTECTED_NAME(name) name
#endif

/*
 * Structure pour stocker les métadonnées des fonctions protégées
 * Cette structure sera utilisée au runtime pour gérer les fonctions
 */
typedef struct {
    const char* name;           /* Nom de la fonction */
    void* address;              /* Adresse de la fonction */
    uint32_t size;              /* Taille en bytes */
    uint8_t* original_bytes;    /* Bytes originaux (NULL si NOPée) */
    uint8_t is_active;          /* 1 si la fonction est restaurée */
} protected_function_info_t;

/* Prototypes pour le système runtime */
#ifdef _WIN32
void* protected_call_request(const char* function_name, void* return_address);
void protected_call_cleanup(const char* function_name);
int protected_function_init(void);
void protected_function_shutdown(void);
int protected_function_register(const char* name, void* address, uint32_t size);
void protected_function_set_send_callback(void (*callback)(struct packet_t*, uint8_t));
void protected_function_handle_response(struct packet_t* pkt);
#endif

/* Forward declaration */
struct packet_t;

#endif /* PROTECTED_FUNCTION_H */
