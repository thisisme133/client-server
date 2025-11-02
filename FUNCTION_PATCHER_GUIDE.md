# Protected Functions System - Complete Guide

## Overview

This system implements a sophisticated protected functions architecture where:
1. Functions are marked with special markers in the client code
2. An external tool extracts and strips these functions from the client binary
3. The server stores the original function bytecode
4. Clients request functions on-demand during runtime
5. Functions are executed in allocated RWX memory

## Architecture Components

### 1. Function Markers (Client)

Functions are defined using the `MARKER_DEF` macro:

```cpp
#include "protected_function.hpp"

// Define a protected function
MARKER_DEF(bool, SetProcessAsCritical)(bool unset = false) {
#ifdef _WIN32
    using RtlSetProcessIsCritical = NTSTATUS(WINAPI*)(BOOLEAN, PBOOLEAN, BOOLEAN);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto fn = reinterpret_cast<RtlSetProcessIsCritical>(
        GetProcAddress(ntdll, "RtlSetProcessIsCritical")
    );
    if (!fn) return false;

    BOOLEAN old_value;
    NTSTATUS status = fn(unset ? FALSE : TRUE, &old_value, FALSE);
    return status >= 0;
#else
    return false;
#endif
}
```

### 2. Calling Protected Functions (Client)

Use `FnProtectGlobal::Call` to invoke protected functions:

```cpp
// Call the protected function
auto result = FnProtectGlobal::Call<bool>(
    MARKER(SetProcessAsCritical),
    true  // parameters...
);

if (result.has_value()) {
    bool success = *result;
    // Function executed successfully
} else {
    // Error: result.error() contains error message
}
```

### 3. Function Patcher Tool (Windows Only)

The `function_patcher.exe` tool extracts functions from a compiled binary using its PDB file.

**Requirements:**
- Windows OS (uses dbghelp.lib)
- Client executable with debug symbols (PDB file)
- Visual Studio or Windows SDK

**Usage:**
```cmd
function_patcher.exe <client.exe> <client.pdb> [output_directory]
```

**Example:**
```cmd
function_patcher.exe client.exe client.pdb functions
```

**What it does:**
1. Parses the PDB file to find protected function symbols
2. Locates functions by name (searches for known protected function names)
3. Extracts RVA (Relative Virtual Address) and size from symbols
4. Converts RVA to file offset using PE section headers
5. Reads original function bytecode from executable
6. Saves each function as `{hash:08X}.bin` (hash = FNV1a of function name)
7. Creates `manifest.json` with function metadata
8. Creates `client_patched.exe` with functions replaced by NOPs (0x90)

**Output Structure:**
```
functions/
├── manifest.json          # Function metadata
├── 7B3C9D2E.bin          # SetProcessAsCritical
├── A4F28E1C.bin          # check_debugger_present
└── ...
```

**manifest.json Format:**
```json
{
  "version": 1,
  "functions": [
    {
      "name": "SetProcessAsCritical",
      "hash": 2067689774,
      "file": "7B3C9D2E.bin",
      "size": 512
    },
    ...
  ]
}
```

### 4. Server Setup

The server loads protected functions from the directory created by the patcher:

```bash
# Linux
./server functions/

# Windows
server.exe functions/
```

The server will:
1. Load `manifest.json` to get function metadata
2. Read each `.bin` file containing function bytecode
3. Store functions in memory indexed by hash
4. Serve functions to clients on request

**Server Startup Output:**
```
Loading protected functions from: functions
Loaded: SetProcessAsCritical (512 bytes)
Loaded: check_debugger_present (512 bytes)
Loaded 2 protected functions
Server listening on port 8888
```

### 5. Client-Server Protocol

When a client calls a protected function:

1. **Client checks cache**: Is function already downloaded?
   - Yes → Execute from RWX memory
   - No → Request from server

2. **Client sends FunctionRequest**:
   ```
   PacketType: FunctionRequest
   Payload: {
     marker_hash: 0x7B3C9D2E,
     timestamp: <current_time>
   }
   ```

3. **Server sends FunctionResponse**:
   ```
   PacketType: FunctionResponse
   Payload: {
     marker_hash: 0x7B3C9D2E,
     code_size: 512,
     code: [<bytecode>]
   }
   ```

4. **Client receives and caches**:
   - Allocate RWX memory (VirtualAlloc/mmap)
   - Copy bytecode to executable memory
   - Store in `FunctionCache`
   - Mark pending request as complete

5. **Client executes function**:
   - Cast memory to function pointer
   - Invoke with provided arguments
   - Return result to caller

## Complete Workflow

### Step 1: Develop and Build Client (Windows)

```cpp
// client.cpp
#include "protected_function.hpp"

MARKER_DEF(bool, MyProtectedFunction)(int param) {
    // Implementation...
    return true;
}

int main() {
    // Initialize connection to server...

    // Call protected function
    auto result = FnProtectGlobal::Call<bool>(
        MARKER(MyProtectedFunction),
        42
    );

    if (result) {
        std::cout << "Result: " << *result << "\n";
    }
}
```

**Build with debug symbols:**
```cmd
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
cmake --build . --config RelWithDebInfo
```

This produces:
- `client.exe` - Executable with debug info
- `client.pdb` - Debug symbols file

### Step 2: Extract Functions (Windows)

```cmd
function_patcher.exe client.exe client.pdb functions
```

**Output:**
```
=== Function Patcher Tool ===
EXE: client.exe
PDB: client.pdb
Output: functions

PDB loaded at base: 0x400000
Found: SetProcessAsCritical at RVA 0x1234 (size: 512)
Found: MyProtectedFunction at RVA 0x5678 (size: 512)
Found 2 protected functions

Extracted 512 bytes from SetProcessAsCritical
Extracted 512 bytes from MyProtectedFunction

Saved: SetProcessAsCritical -> functions/7B3C9D2E.bin
Saved: MyProtectedFunction -> functions/A1B2C3D4.bin

Created manifest: functions/manifest.json

NOPed: SetProcessAsCritical (512 bytes)
NOPed: MyProtectedFunction (512 bytes)
Created patched exe: client_patched.exe

=== Success! ===
2 functions processed
```

### Step 3: Deploy

**Server (Linux or Windows):**
```bash
# Copy functions directory to server
scp -r functions/ user@server:/path/to/server/

# Run server
./server functions/
```

**Client (Windows):**
```cmd
# Distribute client_patched.exe to users
# Original functions are stripped (replaced with NOPs)
client_patched.exe
```

### Step 4: Runtime Execution

1. Client connects to server
2. Client attempts to call `MyProtectedFunction`
3. Function not in cache → Request from server
4. Server sends bytecode
5. Client allocates RWX memory and copies bytecode
6. Client executes function
7. Future calls use cached version (no network request)

## Security Considerations

### Advantages
- **Anti-reverse engineering**: Functions not present in distributed binary
- **Dynamic updates**: Server can update function implementations
- **Access control**: Server can deny function requests
- **Runtime integrity**: Functions verified by server before sending

### Considerations
- **RWX memory**: Required for execution, may trigger EDR alerts
- **Network dependency**: Functions require server connection first time
- **Bytecode security**: Functions sent over encrypted channel
- **Cache persistence**: Functions cached in memory (lost on restart)

## Advanced Features

### 1. Function Versioning

Extend manifest with version field:
```json
{
  "name": "MyFunction",
  "hash": 12345,
  "version": 2,
  "file": "12345_v2.bin"
}
```

### 2. Conditional Function Serving

Server can check client permissions before serving:
```cpp
void handle_function_request(uint32_t marker_hash, ClientSession* client) {
    // Check if client has permission
    if (!client->has_permission(marker_hash)) {
        // Send error or disconnect
        return;
    }

    // Serve function...
}
```

### 3. Function Obfuscation

Additional obfuscation before storage:
```cpp
// XOR encrypt function bytecode
std::vector<uint8_t> obfuscate(std::span<const uint8_t> code) {
    std::vector<uint8_t> result(code.begin(), code.end());
    uint8_t key = 0xAA;
    for (auto& byte : result) {
        byte ^= key;
        key = (key * 7 + 13) & 0xFF;
    }
    return result;
}
```

### 4. JIT Compilation

Instead of raw bytecode, send IR or bytecode for a VM:
- More portable across platforms
- Harder to reverse engineer
- Can include additional runtime checks

## Troubleshooting

### Function Patcher Fails

**Issue**: "PDB not found" or "SymLoadModuleEx failed"
- Ensure PDB file is in same directory as EXE
- Ensure PDB matches EXE (rebuild if needed)
- Check Windows dbghelp.dll is available

**Issue**: "Function not found in PDB"
- Function may be inlined or optimized out
- Add `__declspec(noinline)` to function
- Build with RelWithDebInfo instead of Release

### Server Fails to Load Functions

**Issue**: "Manifest not found"
- Ensure `functions/manifest.json` exists
- Check path passed to server

**Issue**: "Failed to parse manifest"
- Validate JSON syntax
- Check manifest format matches expected structure

### Client Function Call Fails

**Issue**: "No function requester set"
- Call `FnProtectGlobal::set_requester(&client)` after connection

**Issue**: "Failed to receive function from server"
- Check network connection
- Verify server has function (check manifest)
- Check timeout (default 5 seconds)

**Issue**: "Function execution failed"
- RWX memory allocation failed (check permissions)
- Function bytecode corrupted
- Incompatible calling convention or ABI

## Performance

### Latency
- **First call**: Network latency + allocation (~10-100ms)
- **Cached calls**: Direct function call (~nanoseconds)

### Memory
- Each function: ~512 bytes RWX memory
- Cache overhead: ~100 bytes per function metadata

### Network
- Function request: ~16 bytes
- Function response: ~528 bytes (512 + header)
- Total per function: ~544 bytes

## Limitations

### Platform Constraints
- **Function patcher**: Windows only (PDB parsing)
- **RWX memory**: May fail on hardened systems
- **Bytecode portability**: x64 only, not cross-platform

### Size Constraints
- Max function size: ~4KB (MAX_PAYLOAD_SIZE)
- For larger functions: Implement chunked transfer

### Calling Convention
- Functions must use standard calling convention
- C++ member functions not supported (use static)
- Virtual functions not supported

## Future Enhancements

1. **Cross-platform patcher**: Use DWARF for Linux
2. **Function splitting**: Support functions >4KB
3. **Compression**: Compress bytecode before transmission
4. **Integrity checks**: SHA256 hash per function
5. **Cache persistence**: Save to disk for faster startup
6. **ARM support**: Extend to ARM64 bytecode
7. **VM backend**: Custom VM for better portability
