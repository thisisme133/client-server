# TCP Client-Server en C Multi-Plateforme

Serveur et client TCP en C pur avec authentification, chiffrement et heartbeat, supportant Windows, macOS et Linux.

## 🎯 Caractéristiques Principales

### Sécurité et Intégrité
- **CRC32** : Vérification d'intégrité de chaque paquet
- **Chiffrement XOR** : Communications chiffrées avec clé de session
- **Challenge/Réponse** : Authentification par challenge pour chaque heartbeat
- **Heartbeat** : Le client envoie un heartbeat toutes les 5 secondes maximum

### Architecture
- **Multi-threading** : Serveur multi-threadé (un thread par client)
- **Multi-plateforme** : Windows (Winsock2), macOS et Linux (BSD sockets)
- **Logging hiérarchique** : Affichage en arborescence des paquets avec couleurs
- **Optimisé** : Binaires de ~19KB après compilation

### Optimisations
- Utilisation minimale de CRT
- Structures compactes avec `__attribute__((packed))`
- Compression RLE automatique des données
- Types de données minimaux (uint8_t, uint16_t, uint32_t)

## 📁 Structure du Projet

```
client-server/
├── CMakeLists.txt          # Configuration CMake avec optimisations
├── include/                # Headers publics
│   ├── network.h           # Abstraction réseau multi-plateforme
│   ├── packet.h            # Structures de packets
│   ├── compression.h       # Compression/décompression RLE
│   ├── crc.h               # CRC32 pour intégrité
│   ├── crypto.h            # Chiffrement et challenges
│   └── logger.h            # Logging hiérarchique
├── src/
│   ├── common/             # Code partagé
│   │   ├── network.c
│   │   ├── packet.c
│   │   ├── compression.c
│   │   ├── crc.c
│   │   ├── crypto.c
│   │   └── logger.c
│   ├── server/
│   │   └── server.c        # Serveur multi-threadé
│   └── client/
│       └── client.c        # Client avec heartbeat
└── build/                  # Répertoire de build (généré)
```

## 🔐 Workflow de Connexion et Authentification

```
1. Client se connecte au serveur TCP
   │
2. Serveur crée un thread dédié pour ce client
   │
3. Serveur → Client : PKT_CHALLENGE (challenge aléatoire)
   │
4. Serveur → Client : PKT_SESSION_KEY (clé de session 32 bytes)
   │
5. Client → Serveur : PKT_CONNECT (demande d'authentification)
   │
6. Serveur → Client : PKT_ACK (authentification OK)
   │
7. [Boucle] Toutes les 5 secondes :
   │  Client → Serveur : PKT_HEARTBEAT (sequence + challenge_response)
   │  Serveur vérifie la réponse au challenge
   │  Serveur → Client : PKT_CHALLENGE (nouveau challenge)
   │
8. Toutes les communications sont chiffrées après authentification
```

## 📦 Types de Packets

### Packets de Base
- `PKT_CONNECT` : Connexion initiale
- `PKT_DISCONNECT` : Déconnexion
- `PKT_PING` / `PKT_PONG` : Test de connectivité
- `PKT_MESSAGE` : Messages texte
- `PKT_DATA` : Données binaires
- `PKT_ACK` : Acknowledgement
- `PKT_ERROR` : Erreurs

### Nouveaux Packets (Authentification)
- `PKT_HEARTBEAT` : Heartbeat avec réponse au challenge
- `PKT_CHALLENGE` : Challenge envoyé par le serveur
- `PKT_SESSION_KEY` : Clé de session générée par le serveur

## 🏗️ Structure d'un Packet

### Header (8 bytes)
```c
typedef struct __attribute__((packed)) {
    uint8_t type;        /* Type de packet */
    uint8_t flags;       /* Flags (compressed, encrypted, etc.) */
    uint16_t length;     /* Longueur des données */
    uint32_t crc;        /* CRC32 pour intégrité */
} packet_header_t;
```

### Flags
- `PKT_FLAG_COMPRESSED` : Données compressées (RLE)
- `PKT_FLAG_ENCRYPTED` : Données chiffrées (XOR)

### Processus d'Intégrité (CRC)

**Lors de l'envoi :**
1. Calcul du CRC32 sur `header (sans CRC) + payload`
2. Ajout du CRC dans le header
3. Serialization complète du packet

**Lors de la réception :**
1. Deserialization du packet
2. Recalcul du CRC32 sur `header (sans CRC) + payload`
3. Comparaison avec le CRC reçu
4. Rejet si invalide

## 🔧 Compilation

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### Binaires Générés
- `server` : Serveur multi-threadé (~19KB)
- `client` : Client avec heartbeat (~19KB)
- `libcommon.a` : Bibliothèque commune (~28KB)

### Optimisations de Compilation

**Linux (GCC):**
```
-Os -ffunction-sections -fdata-sections
-Wl,--gc-sections --strip-all
```

**macOS (Clang):**
```
-Os -ffunction-sections -fdata-sections
-Wl,-dead_strip
```

**Windows (MSVC):**
```
/Os /GL /LTCG /OPT:REF /OPT:ICF
```

## 🚀 Utilisation

### Démarrer le serveur

```bash
./server
```

Output:
```
═══════════════════════════════════════════════════════════
    TCP Multi-threaded Server with Authentication
═══════════════════════════════════════════════════════════

✓ Server listening on port 8888
```

### Démarrer le client

```bash
./client
```

Output:
```
═══════════════════════════════════════════════════════════
    TCP Client with Heartbeat Authentication
═══════════════════════════════════════════════════════════

→ Connecting to 127.0.0.1:8888...
✓ Connected to server
→ Received challenge: 0xABCD1234
✓ Received session key
→ Requesting authentication
✓ Authenticated with server
→ Sending heartbeat #0
```

## 📊 Logging Hiérarchique

Les logs affichent une arborescence détaillée de chaque packet :

```
[14:25:30] ▼ RECV │ [CHALLENGE]
├── Peer: 127.0.0.1:8888
├── Total Size: 12 bytes
├── Header:
│   ├── Type: 0x09 (CHALLENGE)
│   ├── Flags: 0x00
│   ├── Payload Length: 4 bytes
│   └── CRC32: 0x12AB34CD (VALID)
└── Payload: 4 bytes
    ├── Challenge Value: 0xABCD1234
────────────────────────────────────────────────────────────
```

## ⚙️ Configuration

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

### Modifier l'intervalle du heartbeat

Éditez `src/client/client.c` :
```c
#define HEARTBEAT_INTERVAL 5  /* secondes */
```

### Modifier le timeout heartbeat (serveur)

Éditez `src/server/server.c` :
```c
#define HEARTBEAT_TIMEOUT 10  /* secondes */
```

## 🔒 Sécurité

### Chiffrement
- Algorithme : XOR avec rotation de clé
- Taille de clé : 32 bytes
- Génération : Aléatoire à chaque connexion
- Transmission : En clair lors de l'établissement (PKT_SESSION_KEY)

### Challenge/Réponse
- Challenge : 32 bits aléatoire
- Transformation : Hash non-trivial avec rotations et XOR
- Renouvellement : À chaque heartbeat valide
- Timeout : 10 secondes si pas de heartbeat

### Intégrité (CRC32)
- Algorithme : CRC32 (IEEE 802.3)
- Couverture : Header (type, flags, length) + Payload
- Rejet : Automatique si CRC invalide

## 🧪 Exemple de Test

### Terminal 1 - Serveur
```bash
./server
```

### Terminal 2 - Client
```bash
./client
```

Le client :
- S'authentifie automatiquement
- Envoie un heartbeat toutes les 5 secondes
- Envoie un message de test toutes les 10 secondes
- Affiche tous les packets avec logging hiérarchique

Le serveur :
- Accepte plusieurs clients simultanément (multi-threadé)
- Vérifie les heartbeats et les challenges
- Déconnecte les clients en timeout (>10s sans heartbeat)
- Echo les messages reçus (chiffrés)

## 📝 Personnalisation

### Créer un nouveau type de packet

1. Ajoutez le type dans `include/packet.h` :
```c
typedef enum {
    // ...
    PKT_CUSTOM = 11
} packet_type_t;
```

2. Créez la structure de payload :
```c
typedef struct __attribute__((packed)) {
    uint32_t custom_field;
    uint8_t data[64];
} payload_custom_t;
```

3. Ajoutez le handler dans le serveur et le client :
```c
case PKT_CUSTOM: {
    payload_custom_t custom;
    uint16_t size;
    pkt_get_payload(pkt, &custom, &size);
    // Traitement...
    break;
}
```

4. Mettez à jour le logger dans `src/common/logger.c` pour afficher votre payload.

## 🐛 Dépannage

### Erreur "Failed to bind to port"
Le port 8888 est déjà utilisé. Changez `SERVER_PORT` ou arrêtez l'autre processus.

### "Invalid packet (CRC fail)"
- Corruption réseau
- Incompatibilité de version
- Problème de chiffrement/déchiffrement

### "Heartbeat timeout"
Le client n'a pas envoyé de heartbeat pendant 10+ secondes. Vérifiez :
- La connexion réseau
- Que le client tourne bien
- Les logs du client pour voir s'il envoie les heartbeats

## 🎓 Architecture Technique

### Multi-threading (Serveur)
- **Linux/macOS** : POSIX threads (`pthread`)
- **Windows** : Windows threads (`_beginthreadex`)
- Un thread par client pour traitement parallèle
- Thread principal : Accepte les nouvelles connexions
- Threads clients : Gestion des I/O et heartbeat

### Non-blocking I/O
- Sockets configurés en mode non-blocking
- Polling actif avec délais courts (10ms)
- Gestion des erreurs `EWOULDBLOCK` / `WSAEWOULDBLOCK`

### Gestion Mémoire
- Pas d'allocation dynamique
- Buffers statiques de taille fixe
- Structures packed pour économiser l'espace

## 📈 Performance

- **Latence** : < 1ms en local
- **Throughput** : Limité par la compression/chiffrement
- **Clients simultanés** : 32 max (configurable)
- **Taille binaire** : ~19KB (serveur/client)
- **Empreinte mémoire** : < 1MB par client

## 📜 Licence

Code libre d'utilisation pour projets éducatifs et commerciaux.

## 🤝 Contributions

Ce projet est un exemple éducatif démontrant :
- Architecture client-serveur en C pur
- Multi-threading cross-platform
- Protocole avec authentification
- Chiffrement et intégrité des données
- Logging avancé pour debugging
