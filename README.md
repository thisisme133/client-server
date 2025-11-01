# TCP Client-Server en C Multi-Plateforme

Serveur et client TCP en C pur, optimisés pour des binaires minimaux, supportant Windows, macOS et Linux.

## Caractéristiques

- **Multi-plateforme** : Windows (Winsock2), macOS et Linux (BSD sockets)
- **Optimisé pour la taille** : Binaires de ~15KB après compilation
- **Utilisation minimale de CRT** : Fonctions système natives
- **Système de packets structuré** : Headers compacts (4 bytes) avec types définis
- **Compression** : Compression RLE automatique des données
- **Handlers événementiels** : Gestion propre des connexions/déconnexions/packets
- **Architecture non-bloquante** : Gestion asynchrone des connexions

## Structure du Projet

```
client-server/
├── CMakeLists.txt          # Configuration CMake avec optimisations
├── include/                # Headers publics
│   ├── network.h           # Abstraction réseau multi-plateforme
│   ├── packet.h            # Structures de packets
│   └── compression.h       # Compression/décompression
├── src/
│   ├── common/             # Code partagé
│   │   ├── network.c
│   │   ├── packet.c
│   │   └── compression.c
│   ├── server/
│   │   └── server.c        # Serveur TCP avec handlers
│   └── client/
│       └── client.c        # Client TCP avec handlers
└── build/                  # Répertoire de build (généré)
```

## Types de Packets

- `PKT_CONNECT` : Connexion initiale
- `PKT_DISCONNECT` : Déconnexion
- `PKT_PING` / `PKT_PONG` : Keep-alive
- `PKT_MESSAGE` : Messages texte
- `PKT_DATA` : Données binaires
- `PKT_ACK` : Acknowledgement
- `PKT_ERROR` : Erreurs

## Compilation

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### Optimisations de Compilation

Les flags suivants sont utilisés pour minimiser la taille :

**Linux/macOS (GCC/Clang):**
- `-Os` : Optimisation pour la taille
- `-ffunction-sections -fdata-sections` : Sections séparées pour GC
- `-Wl,--gc-sections --strip-all` : Suppression du code mort
- Strip automatique des symboles

**Windows (MSVC):**
- `/Os` : Optimisation pour la taille
- `/GL /LTCG` : Link-time code generation
- `/OPT:REF /OPT:ICF` : Optimisations du linker

## Utilisation

### Démarrer le serveur

```bash
./server
```

Le serveur écoute sur le port `8888` par défaut.

### Démarrer le client

```bash
./client
```

Le client se connecte à `127.0.0.1:8888` par défaut.

## Personnalisation

### Modifier le port du serveur

Éditez `src/server/server.c` :
```c
#define SERVER_PORT 8888
```

### Modifier l'adresse du serveur (client)

Éditez `src/client/client.c` :
```c
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
```

### Créer des nouveaux types de packets

1. Ajoutez le type dans `include/packet.h` :
```c
typedef enum {
    // ...
    PKT_CUSTOM = 8
} packet_type_t;
```

2. Créez la structure de payload :
```c
typedef struct __attribute__((packed)) {
    uint8_t field1;
    uint16_t field2;
} payload_custom_t;
```

3. Ajoutez le handler dans le switch case :

**Serveur (`src/server/server.c`):**
```c
static void handle_packet(uint8_t client_id, packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        // ...
        case PKT_CUSTOM:
            handle_custom(client_id, pkt);
            break;
    }
}
```

**Client (`src/client/client.c`):**
```c
static void handle_packet(packet_t* pkt) {
    switch (pkt_get_type(pkt)) {
        // ...
        case PKT_CUSTOM:
            handle_custom(pkt);
            break;
    }
}
```

## Compression

La compression RLE est automatiquement appliquée si bénéfique (>20% de répétitions).
Le flag `PKT_FLAG_COMPRESSED` est automatiquement géré.

## Taille des Binaires

Après compilation et strip :
- **server** : ~15KB
- **client** : ~15KB
- **libcommon.a** : ~9KB

## Architecture des Handlers

### Serveur

- `handle_connect()` : Nouvelle connexion
- `handle_disconnect()` : Déconnexion
- `handle_packet()` : Router principal (switch case)
- `handle_ping()`, `handle_message()`, `handle_data()` : Handlers spécifiques

### Client

- `handle_connect_response()` : Connexion établie
- `handle_disconnect_response()` : Déconnexion
- `handle_packet()` : Router principal (switch case)
- `handle_ack()`, `handle_pong()`, `handle_message()`, `handle_error()` : Handlers spécifiques

## Licence

Code libre d'utilisation.
