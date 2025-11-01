# Système de Fonctions Protégées

Ce système permet de protéger des fonctions dans le client en les "NOP-ant" (remplacement par des NOPs) et en les restaurant à la demande depuis le serveur.

## Vue d'ensemble

1. **Marquage** : Les fonctions sont marquées avec le macro `PROTECTED_FUNCTION`
2. **Patching** : L'outil `function_patcher` lit le PDB, trouve les fonctions marquées, et les remplace par des NOPs
3. **Runtime** : Quand une fonction NOPée est appelée, le client la demande au serveur
4. **Exécution** : Le client restaure temporairement la fonction, l'exécute, puis la re-NOP

## Utilisation

### 1. Marquer une fonction dans le code source

```c
#include "protected_function.h"

// Fonction normale
void my_normal_function() {
    printf("This is a normal function\n");
}

// Fonction protégée
PROTECTED_FUNCTION
void PROTECTED_NAME(my_protected_function)() {
    printf("This is a protected function\n");
    // Code sensible ici
}
```

**Important** :
- Utilisez `PROTECTED_FUNCTION` avant la définition
- Utilisez `PROTECTED_NAME(nom)` pour le nom de la fonction
- Le nom sera automatiquement préfixé avec `PROTECTED_` dans les symboles

### 2. Compiler le client avec les symboles de debug (PDB)

Sur Windows avec MSVC:
```cmd
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --config RelWithDebInfo
```

Ceci génèrera `client.exe` et `client.pdb` dans le même dossier.

### 3. Utiliser l'outil de patching

#### Compilation de l'outil (Windows uniquement)

L'outil est automatiquement compilé sur Windows :
```cmd
cd build
# L'exécutable function_patcher.exe sera dans build/tools/
```

#### Utilisation

```cmd
cd build
tools\function_patcher.exe client.exe
```

**Sortie attendue** :
```
═══════════════════════════════════════════════════════════
           Function Patcher Tool (PDB-based)
═══════════════════════════════════════════════════════════

→ Target executable: client.exe

→ Loading PDB symbols...
✓ Symbols loaded at base: 0x10000000

→ Searching for protected functions...
  [0] Found: PROTECTED_my_protected_function (RVA: 0x00001234, Size: 128 bytes)
  [1] Found: PROTECTED_another_function (RVA: 0x00005678, Size: 256 bytes)

✓ Found 2 protected function(s)

→ Opening executable for patching...
✓ Executable opened

→ Patching functions...
  → Patching: PROTECTED_my_protected_function
    RVA: 0x00001234, File offset: 0x00000A34, Size: 128 bytes
  ✓ Saved original bytes to: protected_functions/PROTECTED_my_protected_function.bytes (128 bytes)
  ✓ Replaced with NOPs (128 bytes)

  ...

✓ Metadata saved to: protected_functions/metadata.txt

═══════════════════════════════════════════════════════════
✓ Patching complete!
  - 2 function(s) processed
  - Original bytes saved in: protected_functions/
  - Executable patched with NOPs
═══════════════════════════════════════════════════════════
```

### 4. Déployer le client et les fichiers .bytes

Copiez les fichiers suivants vers le serveur :
```
/server_directory/
├── server.exe
└── protected_functions/
    ├── PROTECTED_my_protected_function.bytes
    ├── PROTECTED_another_function.bytes
    └── metadata.txt
```

Le client patchée peut être distribué :
```
/client_directory/
└── client.exe  (avec les fonctions NOPées)
```

### 5. Runtime - Appel de fonctions protégées

Le système fonctionne automatiquement au runtime, mais pour l'utiliser manuellement :

```c
#include "protected_function.h"

void some_function() {
    // Enregistrer la fonction protégée (si nécessaire)
    protected_function_register("PROTECTED_my_protected_function",
                                 (void*)&PROTECTED_my_protected_function,
                                 128);  // taille en bytes

    // Demander la fonction au serveur
    void* func_ptr = protected_call_request("PROTECTED_my_protected_function", NULL);

    if (func_ptr) {
        // Appeler la fonction restaurée
        typedef void (*func_t)(void);
        func_t my_func = (func_t)func_ptr;
        my_func();

        // Nettoyer (re-NOP la fonction)
        protected_call_cleanup("PROTECTED_my_protected_function");
    }
}
```

## Architecture

### Marquage (Compile-time)

Le macro `PROTECTED_FUNCTION` utilise :
- `__declspec(code_seg(".protect"))` : Place la fonction dans une section spéciale
- `__declspec(noinline)` : Empêche l'inlining
- `PROTECTED_` prefix : Facilite la détection dans le PDB

### Outil de Patching

L'outil `function_patcher` :
1. Charge le PDB avec `DbgHelp.dll` (API Windows)
2. Énumère les symboles avec `SymEnumSymbols()`
3. Trouve ceux commençant par `PROTECTED_`
4. Convertit les RVAs en offsets de fichier
5. Lit et sauvegarde les bytes originaux
6. Remplace par des NOPs (0x90)

### Protocole Runtime

#### Client → Serveur : `PKT_FUNCTION_REQUEST`
```c
{
    char function_name[256];  // "PROTECTED_my_function"
}
```

#### Serveur → Client : `PKT_FUNCTION_RESPONSE`
```c
{
    char function_name[256];
    uint32_t size;
    uint8_t success;
    uint8_t data[...];  // Bytes de la fonction
}
```

### Restauration et Exécution

1. **Demande** : Client envoie `PKT_FUNCTION_REQUEST`
2. **Chargement** : Serveur lit le fichier `.bytes`
3. **Envoi** : Serveur envoie `PKT_FUNCTION_RESPONSE`
4. **Restauration** : Client change la protection mémoire (`VirtualProtect`)
5. **Écriture** : Client écrit les bytes originaux
6. **Exécution** : Client appelle la fonction
7. **Cleanup** : Client re-NOP la fonction

## Structure des Fichiers

```
/project/
├── include/
│   ├── protected_function.h           # Header principal avec macros
│   └── protected_function_server.h    # API serveur
├── src/
│   ├── client/
│   │   └── protected_function_client.c  # Implémentation client
│   └── server/
│       └── protected_function_server.c  # Implémentation serveur
├── tools/
│   ├── function_patcher.c             # Outil de patching
│   └── CMakeLists.txt
└── protected_functions/               # Généré par function_patcher
    ├── PROTECTED_xxx.bytes
    ├── PROTECTED_yyy.bytes
    └── metadata.txt
```

## Sécurité

Ce système fournit une obfuscation légère :
- ✅ Les fonctions ne sont pas présentes dans le binaire client
- ✅ Elles sont demandées à la demande seulement
- ✅ Elles sont ré-NOPées après exécution
- ⚠️ Les bytes sont transmis en clair (utiliser encryption)
- ⚠️ Un attaqueur avec accès au serveur peut récupérer les fonctions

## Limitations

- **Windows uniquement** : Le système de patching utilise l'API DbgHelp de Windows
- **PDB requis** : Le fichier PDB doit être disponible pour le patching
- **Taille limitée** : Les fonctions doivent tenir dans un packet (< 755 bytes par défaut)
- **Performance** : Chaque appel nécessite une requête réseau

## Exemple Complet

Voir les fichiers de test dans `/examples/protected_function_example.c` (à créer).

## Dépannage

### "Failed to load symbols"
- Vérifiez que le fichier `.pdb` est dans le même dossier que `.exe`
- Recompilez avec les symboles de debug activés

### "Function file not found"
- Vérifiez que le dossier `protected_functions/` existe côté serveur
- Vérifiez les permissions du dossier

### "Failed to change memory protection"
- Sur Windows, certaines protections peuvent bloquer `VirtualProtect`
- Exécutez en tant qu'Administrateur

### Les fonctions ne sont pas détectées
- Vérifiez que vous utilisez `PROTECTED_FUNCTION` ET `PROTECTED_NAME()`
- Vérifiez que la fonction n'est pas inlinée par le compilateur

## API Reference

### Client

```c
// Initialiser le système
int protected_function_init(void);

// Définir le callback d'envoi de packets
void protected_function_set_send_callback(void (*callback)(packet_t*, uint8_t));

// Enregistrer une fonction
int protected_function_register(const char* name, void* address, uint32_t size);

// Demander et restaurer une fonction
void* protected_call_request(const char* function_name, void* return_address);

// Nettoyer et re-NOPer
void protected_call_cleanup(const char* function_name);

// Handler pour les réponses du serveur
void protected_function_handle_response(packet_t* pkt);

// Shutdown
void protected_function_shutdown(void);
```

### Serveur

```c
// Charger les bytes d'une fonction
int load_protected_function(const char* function_name, uint8_t* buffer, uint32_t* size);

// Handler pour les requêtes client
void handle_function_request(uint8_t client_id, packet_t* pkt,
                              void (*send_func)(uint8_t, packet_t*, uint8_t));
```

## License

Voir LICENSE dans le dossier racine du projet.
