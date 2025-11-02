# Analyse des Fonctions Client à Protéger

## Vue d'ensemble

Le fichier `client.cpp` contient plusieurs fonctions sensibles qui devraient être **strippées** de l'exécutable distribué et servies dynamiquement par le serveur. Ces fonctions révèlent la logique interne du client et peuvent être analysées par reverse engineering.

## Fonctions Identifiées pour Protection

### 1. **check_debugger_present()** ⭐ PRIORITÉ HAUTE
**Localisation**: `client.cpp:248-282`
**Taille estimée**: ~35 lignes / ~400 bytes

**Description**: Détecte la présence d'un debugger avec 5 méthodes différentes

**Techniques utilisées**:
- `IsDebuggerPresent()` - API Windows standard
- `CheckRemoteDebuggerPresent()` - Détection de debugger distant
- `NtQueryInformationProcess(ProcessDebugPort)` - Syscall direct
- Hardware breakpoints (DR0-DR7) via `GetThreadContext()`
- PEB `BeingDebugged` flag - Lecture directe de la structure PEB

**Pourquoi protéger**:
- Révèle toutes les méthodes de détection utilisées
- Un attaquant peut patcher les checks individuellement
- Contient des constantes hardcodées (ProcessDebugPort = 7)
- L'offset PEB est visible (__readgsqword(0x60))

**Intérêt de stripper**:
- ✅ Masque les techniques anti-debug
- ✅ Peut être mise à jour sans redéployer le client
- ✅ Peut vérifier de nouvelles méthodes de détection
- ✅ Le reverse engineer ne voit que le call, pas la logique

**Conversion proposée**:
```cpp
// Avant (dans client.cpp)
bool check_debugger_present() {
    // ... logique complète visible
}

// Après (fonction protégée dans protected_security.hpp)
MARKER_DEF(bool, check_debugger_present)() {
    // ... logique complète servie par le serveur
}

// Dans client.cpp
auto result = protect::FnProtectGlobal::Call<bool>(
    MARKER(check_debugger_present)
);
if (result && *result) {
    // Debugger détecté
}
```

---

### 2. **check_vm_present()** ⭐ PRIORITÉ HAUTE
**Localisation**: `client.cpp:284-325`
**Taille estimée**: ~42 lignes / ~500 bytes

**Description**: Détecte l'exécution dans une machine virtuelle avec 4 méthodes

**Techniques utilisées**:
- **CPUID hypervisor bit** (ECX bit 31) - Detection matérielle
- **CPUID vendor string** (0x40000000) - VMware, VBox, Hyper-V
- **RDTSC timing attack** - Mesure de cycles CPU (threshold: 1M cycles)
- **Registry keys** - VBoxGuest, VMware Tools

**Pourquoi protéger**:
- Révèle les signatures VM recherchées ("VMware", "VBoxVBox", "Microsoft Hv")
- Le threshold de timing (1000000 cycles) est hardcodé
- Les chemins de registre complets sont visibles
- Un sandbox peut patcher ces checks facilement

**Intérêt de stripper**:
- ✅ Masque les signatures VM recherchées
- ✅ Cache le threshold de timing
- ✅ Empêche le patching des checks individuels
- ✅ Peut ajouter de nouvelles VM à détecter dynamiquement

**Registre keys hardcodés visibles**:
```cpp
"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"
"SOFTWARE\\VMware, Inc.\\VMware Tools"
```

---

### 3. **find_process_by_name()** ⭐ PRIORITÉ MOYENNE
**Localisation**: `client.cpp:402-424`
**Taille estimée**: ~23 lignes / ~300 bytes

**Description**: Enumère les processus pour trouver un PID par nom

**Techniques utilisées**:
- `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` - Snapshot de processus
- `Process32FirstW/Process32NextW` - Iteration sur processus
- `WideCharToMultiByte` - Conversion Unicode → UTF-8

**Pourquoi protéger**:
- Révèle la méthode d'énumération (Toolhelp32 vs NtQuerySystemInformation)
- Un EDR peut détecter ce pattern d'énumération
- Le nom recherché ("notepad.exe") est visible dans inject_pe()

**Intérêt de stripper**:
- ⚠️ Modéré - La logique est simple
- ✅ Peut switcher entre différentes méthodes d'enumération
- ✅ Peut obfusquer le processus cible
- ✅ Cache le pattern d'API calls

---

### 4. **validate_pe()** ⭐ PRIORITÉ BASSE
**Localisation**: `client.cpp:426-440`
**Taille estimée**: ~15 lignes / ~200 bytes

**Description**: Valide les headers PE (DOS + NT signatures)

**Techniques utilisées**:
- Vérification `IMAGE_DOS_SIGNATURE` (MZ)
- Vérification `IMAGE_NT_SIGNATURE` (PE)
- Validation des offsets et tailles

**Pourquoi protéger**:
- ⚠️ Logique standard PE bien documentée
- Peu d'intérêt à masquer (technique publique)

**Intérêt de stripper**:
- ❌ Faible - Logique PE standard
- ✅ Peut ajouter des validations custom
- ✅ Petit gain en taille

---

### 5. **inject_pe()** ⭐⭐⭐ PRIORITÉ CRITIQUE
**Localisation**: `client.cpp:442-540`
**Taille estimée**: ~99 lignes / ~1200 bytes

**Description**: Injection complète d'un PE dans un processus distant via syscalls

**Techniques utilisées**:
- Parsing complet PE (DOS header, NT headers, sections)
- `NtOpenProcess` via syscall manager
- `NtAllocateVirtualMemory` - Allocation mémoire distante (PAGE_EXECUTE_READWRITE)
- `NtWriteVirtualMemory` - Ecriture du PE section par section
- **Relocation processing** - Patch des adresses (IMAGE_REL_BASED_DIR64)
- `NtProtectVirtualMemory` - Protection mémoire (PAGE_EXECUTE_READ)
- `NtCreateThreadEx` - Création thread au entry point

**Pourquoi protéger** (CRITIQUE):
- 🔴 **Révèle tout le flow d'injection PE**
- 🔴 **Montre l'utilisation des syscalls directs**
- 🔴 **Le calcul de delta de relocation est visible**
- 🔴 **Les protections mémoire utilisées sont exposées**
- 🔴 **Le processus cible (notepad.exe) est hardcodé**
- 🔴 **EDR/AV peut analyser statiquement le pattern complet**

**Intérêt de stripper** (MAXIMUM):
- ✅✅✅ **MASQUE TOTALEMENT LA LOGIQUE D'INJECTION**
- ✅ Empêche l'analyse statique du loader PE
- ✅ Cache l'utilisation de syscalls directs
- ✅ Peut changer de méthode d'injection dynamiquement
- ✅ Le binaire distribué ne contient AUCUNE trace d'injection
- ✅ Peut implémenter différentes techniques (manual mapping, reflective loading, etc.)

**Taille**:
- ⚠️ ~1200 bytes - Peut dépasser la limite de payload (4KB OK)

---

## Analyse de Dépendances

### Membres d'instance utilisés
Certaines fonctions accèdent à des membres de `GameClient`:
- `inject_pe()` → utilise `pe_buffer_`, `pe_entry_rva_`, `target_process_`, `send_packet()`
- `send_challenge_response()` → utilise `current_challenge_`, `send_packet()`

**Solution**:
- Passer les données nécessaires en paramètres
- Ou créer des fonctions statiques/libres qui reçoivent tout en paramètre

### Fonctions standalone (faciles à protéger)
Ces fonctions peuvent être extraites directement:
- ✅ `check_debugger_present()` - Aucune dépendance d'instance
- ✅ `check_vm_present()` - Aucune dépendance d'instance
- ✅ `find_process_by_name()` - Aucune dépendance d'instance
- ✅ `validate_pe()` - Prend un buffer en paramètre (refactoring nécessaire)

### Fonctions avec dépendances (refactoring nécessaire)
- ⚠️ `inject_pe()` - Accède à plusieurs membres, appelle `send_packet()`

---

## Proposition de Refactoring

### Créer un fichier `protected_client_functions.hpp`

```cpp
#pragma once

#include "protected_function.hpp"
#include "syscalls.hpp"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace client_protected {

// Anti-Debug Check
MARKER_DEF(bool, check_debugger_present)() {
    // ... implémentation complète
    return false;
}

// Anti-VM Check
MARKER_DEF(bool, check_vm_present)() {
    // ... implémentation complète
    return false;
}

// Process Enumeration
MARKER_DEF(uint32_t, find_process_by_name)(const char* process_name) {
    // ... implémentation complète
    return 0;
}

// PE Validation
MARKER_DEF(bool, validate_pe)(const uint8_t* pe_data, size_t size) {
    // ... implémentation complète
    return false;
}

// PE Injection (CRITICAL)
MARKER_DEF(bool, inject_pe)(
    const uint8_t* pe_data,
    size_t pe_size,
    uint32_t entry_rva,
    const char* target_process,
    uint64_t* out_base_address
) {
    // ... implémentation complète injection
    return false;
}

} // namespace client_protected
```

### Utilisation dans `client.cpp`

```cpp
// Avant
if (check_debugger_present()) {
    return;
}

// Après
auto debug_result = protect::FnProtectGlobal::Call<bool>(
    MARKER(check_debugger_present)
);
if (debug_result && *debug_result) {
    return; // Debugger detected
}

// Avant
inject_pe();

// Après
uint64_t base_address = 0;
auto inject_result = protect::FnProtectGlobal::Call<bool>(
    MARKER(inject_pe),
    pe_buffer_.data(),
    pe_buffer_.size(),
    pe_entry_rva_,
    target_process_.empty() ? "notepad.exe" : target_process_.c_str(),
    &base_address
);
```

---

## Workflow de Protection

### Étape 1: Extraire les fonctions
1. Créer `include/protected_client_functions.hpp`
2. Déplacer les 5 fonctions avec `MARKER_DEF`
3. Rendre les fonctions indépendantes (passer params au lieu de membres)

### Étape 2: Modifier le client
1. Supprimer les implémentations originales dans `client.cpp`
2. Remplacer les appels directs par `FnProtectGlobal::Call`
3. Gérer les `std::expected` retours

### Étape 3: Build avec debug symbols
```cmd
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
cmake --build . --config RelWithDebInfo
# Produit: client.exe + client.pdb
```

### Étape 4: Patcher
```cmd
function_patcher.exe client.exe client.pdb functions/
# Produit: client_patched.exe (fonctions NOPées)
# Produit: functions/*.bin (bytecode original)
# Produit: functions/manifest.json
```

### Étape 5: Déployer
```bash
# Server
./server functions/

# Client (distribué)
client_patched.exe → Aucune trace des fonctions sensibles!
```

---

## Bénéfices de la Protection

### Sécurité
- ✅ **Anti-reverse engineering**: Fonctions absentes du binaire distribué
- ✅ **Anti-tampering**: Impossible de patcher ce qui n'existe pas
- ✅ **Dynamic updates**: Serveur peut modifier la logique sans redéployer
- ✅ **Analysis prevention**: Outils d'analyse statique ne voient rien

### Analyse Comparative

| Fonction | Binaire Normal | Binaire Protégé |
|----------|----------------|-----------------|
| `check_debugger_present` | 5 méthodes visibles, facile à patcher | `0x90 0x90 0x90...` (NOPs) |
| `check_vm_present` | Signatures VM exposées | `0x90 0x90 0x90...` (NOPs) |
| `inject_pe` | **TOUT le loader visible** | `0x90 0x90 0x90...` (NOPs) |

### Taille du Binaire
```
Avant:  27KB avec toutes les fonctions
Après:  ~24KB avec fonctions strippées (-3KB)
        + ~2KB bytecode sur serveur
```

### Performance
- **Premier appel**: Latence réseau (~10-100ms) + allocation RWX
- **Exécution**: Identique à fonction normale
- **Après exécution**: Mémoire RWX immédiatement libérée ✨

### Détection Runtime
```
Avant: Debugger peut voir la fonction en mémoire
Après: Fonction existe seulement pendant l'exécution (RAII)
       → Libérée immédiatement après
       → Fenêtre de détection minimale
```

---

## Recommandations

### Ordre de Priorité
1. **inject_pe()** → 🔴 CRITIQUE - Masque tout le loader PE
2. **check_debugger_present()** → 🟠 HAUTE - Masque anti-debug
3. **check_vm_present()** → 🟠 HAUTE - Masque anti-VM
4. **find_process_by_name()** → 🟡 MOYENNE - Masque enumération
5. **validate_pe()** → 🟢 BASSE - Technique standard

### Fonctions Additionnelles à Considérer
- `send_challenge_response()` - Révèle le flow d'authentification
- Parties de `handle_pe_chunk()` - Assemblage du PE
- Futures fonctions sensibles (keystroke injection, hooks, etc.)

### Limitations Actuelles
- ⚠️ MAX_PAYLOAD_SIZE = ~4KB par fonction
- ⚠️ `inject_pe()` fait ~1.2KB → OK
- ⚠️ Pour fonctions >4KB: implémenter chunked transfer

---

## Conclusion

Les 5 fonctions identifiées sont des **cibles idéales** pour le système de protected functions. La fonction `inject_pe()` en particulier est **critique** car elle révèle toute la logique d'injection PE via syscalls directs.

En strippant ces fonctions:
- Le binaire distribué ne contient aucune trace de la logique sensible
- L'analyse statique devient impossible
- Le patching devient impossible (rien à patcher)
- La fenêtre de détection en mémoire est minimale (libération immédiate post-exécution)

**Prochaine étape**: Créer `protected_client_functions.hpp` et refactoriser le code.
