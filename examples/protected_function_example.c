/*
 * Exemple d'utilisation du système de fonctions protégées
 *
 * Ce fichier montre comment marquer des fonctions pour qu'elles soient
 * protégées par le système de NOPing/restauration à la demande.
 */

#include "protected_function.h"
#include <stdio.h>

/*
 * ============================================================================
 * FONCTIONS NORMALES (non protégées)
 * ============================================================================
 */

void normal_function_1() {
    printf("This is a normal function - always available\n");
}

void normal_function_2() {
    printf("Another normal function\n");
}

/*
 * ============================================================================
 * FONCTIONS PROTÉGÉES
 * ============================================================================
 *
 * Ces fonctions seront:
 * 1. Détectées automatiquement via le PDB (nom PROTECTED_*)
 * 2. Sauvegardées dans des fichiers .bytes
 * 3. Remplacées par des NOPs dans le client.exe
 * 4. Restaurées à la demande depuis le serveur
 */

/*
 * Exemple 1: Fonction de validation de licence
 * Cette fonction vérifie une clé de licence et ne devrait être
 * disponible qu'à la demande pour éviter le reverse engineering
 */
PROTECTED_FUNCTION
int PROTECTED_NAME(validate_license)(const char* license_key) {
    printf("→ Validating license key: %s\n", license_key);

    /* Algorithme de validation complexe ici */
    const char* valid_key = "ABC-123-XYZ-789";

    for (int i = 0; license_key[i] != '\0' && valid_key[i] != '\0'; i++) {
        if (license_key[i] != valid_key[i]) {
            printf("✗ Invalid license key\n");
            return 0;
        }
    }

    printf("✓ Valid license key\n");
    return 1;
}

/*
 * Exemple 2: Fonction de décryption sensible
 * Cette fonction contient un algorithme de décryption qui ne devrait
 * pas être visible dans le binaire client
 */
PROTECTED_FUNCTION
void PROTECTED_NAME(decrypt_sensitive_data)(const uint8_t* encrypted,
                                             uint8_t* decrypted,
                                             uint32_t size) {
    printf("→ Decrypting %u bytes of sensitive data...\n", size);

    /* Algorithme de décryption "secret" */
    const uint8_t secret_key = 0x42;

    for (uint32_t i = 0; i < size; i++) {
        decrypted[i] = encrypted[i] ^ secret_key;
    }

    printf("✓ Data decrypted\n");
}

/*
 * Exemple 3: Anti-debug check
 * Cette fonction vérifie la présence d'un debugger
 */
PROTECTED_FUNCTION
int PROTECTED_NAME(check_debugger)(void) {
    printf("→ Checking for debugger...\n");

#ifdef _WIN32
    /* Sur Windows, IsDebuggerPresent() */
    #include <windows.h>
    if (IsDebuggerPresent()) {
        printf("⚠ Debugger detected!\n");
        return 1;
    }
#endif

    printf("✓ No debugger detected\n");
    return 0;
}

/*
 * Exemple 4: Calcul de checksum du code
 * Vérifie l'intégrité du code en mémoire
 */
PROTECTED_FUNCTION
uint32_t PROTECTED_NAME(calculate_code_checksum)(void) {
    printf("→ Calculating code checksum...\n");

    /* Calcul simplifié - dans la vraie vie, utiliser un vrai hash */
    uint32_t checksum = 0x12345678;

    printf("✓ Checksum: 0x%08X\n", checksum);
    return checksum;
}

/*
 * Exemple 5: Fonction d'authentification premium
 * Débloque des fonctionnalités premium
 */
PROTECTED_FUNCTION
int PROTECTED_NAME(authenticate_premium)(const char* username, const char* token) {
    printf("→ Authenticating premium user: %s\n", username);

    /* Vérification du token */
    if (strlen(token) < 16) {
        printf("✗ Invalid premium token\n");
        return 0;
    }

    printf("✓ Premium user authenticated\n");
    return 1;
}

/*
 * ============================================================================
 * EXEMPLE D'UTILISATION
 * ============================================================================
 */

#ifdef _WIN32  /* Le système de fonctions protégées est Windows-only */

void example_usage(void) {
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("        Protected Functions - Example Usage\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    /*
     * NOTE: Dans un vrai programme, protected_function_init() et
     * protected_function_set_send_callback() seraient appelés au démarrage
     */

    /* Exemple 1: Valider une licence */
    printf("Example 1: License Validation\n");
    printf("───────────────────────────────────────────────────────────\n");

    void* func = protected_call_request("PROTECTED_validate_license", NULL);
    if (func) {
        typedef int (*validate_func_t)(const char*);
        validate_func_t validate = (validate_func_t)func;

        int result = validate("ABC-123-XYZ-789");
        printf("Result: %d\n", result);

        protected_call_cleanup("PROTECTED_validate_license");
    }

    printf("\n");

    /* Exemple 2: Décrypter des données */
    printf("Example 2: Sensitive Data Decryption\n");
    printf("───────────────────────────────────────────────────────────\n");

    uint8_t encrypted[] = {0x20, 0x25, 0x26, 0x26, 0x2D};  /* "Hello" XOR 0x42 */
    uint8_t decrypted[6] = {0};

    func = protected_call_request("PROTECTED_decrypt_sensitive_data", NULL);
    if (func) {
        typedef void (*decrypt_func_t)(const uint8_t*, uint8_t*, uint32_t);
        decrypt_func_t decrypt = (decrypt_func_t)func;

        decrypt(encrypted, decrypted, 5);
        decrypted[5] = '\0';
        printf("Decrypted text: %s\n", decrypted);

        protected_call_cleanup("PROTECTED_decrypt_sensitive_data");
    }

    printf("\n");

    /* Exemple 3: Vérifier le debugger */
    printf("Example 3: Debugger Detection\n");
    printf("───────────────────────────────────────────────────────────\n");

    func = protected_call_request("PROTECTED_check_debugger", NULL);
    if (func) {
        typedef int (*check_func_t)(void);
        check_func_t check = (check_func_t)func;

        int is_debugged = check();
        if (is_debugged) {
            printf("⚠ Application is being debugged - exiting\n");
            /* exit(1); */
        }

        protected_call_cleanup("PROTECTED_check_debugger");
    }

    printf("\n");

    printf("═══════════════════════════════════════════════════════════\n");
    printf("✓ All examples completed\n");
    printf("═══════════════════════════════════════════════════════════\n\n");
}

#else

void example_usage(void) {
    printf("Protected functions are only supported on Windows\n");
}

#endif

/*
 * ============================================================================
 * NOTES IMPORTANTES
 * ============================================================================
 *
 * 1. COMPILATION:
 *    - Compilez avec les symboles de debug pour générer le PDB
 *    - cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
 *    - cmake --build build
 *
 * 2. PATCHING:
 *    - Exécutez function_patcher.exe sur client.exe
 *    - Ceci génère les fichiers .bytes et NOP les fonctions
 *
 * 3. DÉPLOIEMENT:
 *    - Serveur: Copiez protected_functions/*.bytes
 *    - Client: Distribuez le client.exe patchée (avec NOPs)
 *
 * 4. EXÉCUTION:
 *    - Au runtime, les fonctions sont demandées au serveur
 *    - Le serveur lit les .bytes et les envoie
 *    - Le client restaure temporairement, exécute, puis re-NOP
 *
 * 5. BONNES PRATIQUES:
 *    - Ne protégez que les fonctions vraiment sensibles
 *    - Les fonctions protégées ont un overhead réseau
 *    - Utilisez l'encryption sur les packets pour plus de sécurité
 *    - Testez bien le système avant déploiement
 */
