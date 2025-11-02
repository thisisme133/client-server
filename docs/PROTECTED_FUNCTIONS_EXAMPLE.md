# Protected Functions - Practical Examples

## Example 1: Adding a New Protected Function

### Step 1: Define the Function

Create or modify a header file (e.g., `include/protected_security.hpp`):

```cpp
#pragma once

#include "protected_function.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace security {

// Check if debugger is present
MARKER_DEF(bool, check_debugger_present)() {
#ifdef _WIN32
    // Method 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return true;
    }

    // Method 2: CheckRemoteDebuggerPresent
    BOOL remote_debug = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debug)) {
        if (remote_debug) return true;
    }

    // Method 3: PEB BeingDebugged flag
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (peb->BeingDebugged) {
        return true;
    }

    return false;
#else
    return false;
#endif
}

// Check for VM environment
MARKER_DEF(bool, check_vm_present)() {
#ifdef _WIN32
    // Check CPUID for hypervisor
    int cpuid_info[4];
    __cpuid(cpuid_info, 1);

    // Bit 31 of ECX indicates hypervisor presence
    if (cpuid_info[2] & (1 << 31)) {
        return true;
    }

    // Check for VMware/VirtualBox registry keys
    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegCloseKey(key);
        return true;
    }

    return false;
#else
    return false;
#endif
}

// Elevate process priority
MARKER_DEF(bool, elevate_priority)() {
#ifdef _WIN32
    return SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
#else
    return false;
#endif
}

} // namespace security
```

### Step 2: Use in Client Code

In your `client.cpp`:

```cpp
#include "protected_security.hpp"
#include "protected_function.hpp"

int main() {
    // Initialize network connection...
    GameClient client;

    if (!client.connect("127.0.0.1", 8888)) {
        return 1;
    }

    // Set function requester
    protect::FnProtectGlobal::set_requester(&client);

    // Use protected functions
    std::cout << "Performing security checks...\n";

    // Check for debugger
    auto debug_result = protect::FnProtectGlobal::Call<bool>(
        MARKER(check_debugger_present)
    );

    if (!debug_result) {
        std::cerr << "Failed to check debugger: " << debug_result.error() << "\n";
        return 1;
    }

    if (*debug_result) {
        std::cerr << "Debugger detected! Exiting.\n";
        return 1;
    }

    // Check for VM
    auto vm_result = protect::FnProtectGlobal::Call<bool>(
        MARKER(check_vm_present)
    );

    if (*vm_result) {
        std::cerr << "Virtual machine detected! Exiting.\n";
        return 1;
    }

    // Elevate priority
    auto priority_result = protect::FnProtectGlobal::Call<bool>(
        MARKER(elevate_priority)
    );

    if (*priority_result) {
        std::cout << "Process priority elevated\n";
    }

    std::cout << "All security checks passed!\n";

    // Continue with normal operation...
    return 0;
}
```

### Step 3: Update Function Patcher

Modify `tools/function_patcher.cpp` to include your new functions:

```cpp
static const std::vector<std::string> protected_functions = {
    "SetProcessAsCritical",
    "check_debugger_present",
    "check_vm_present",
    "elevate_priority",         // Add new function names here
    "find_process_by_name",
    "validate_pe",
    "inject_pe"
};
```

### Step 4: Build and Patch

```cmd
# Build client with debug symbols
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
cmake --build . --config RelWithDebInfo

# Run patcher
function_patcher.exe client.exe client.pdb functions

# You should see:
# Found: check_debugger_present at RVA 0x1234 (size: 512)
# Found: check_vm_present at RVA 0x5678 (size: 512)
# Found: elevate_priority at RVA 0x9ABC (size: 512)
```

## Example 2: Error Handling

```cpp
#include "protected_function.hpp"

void safe_function_call() {
    auto result = protect::FnProtectGlobal::Call<bool>(
        MARKER(check_debugger_present)
    );

    if (!result) {
        // Handle error
        std::string_view error = result.error();

        if (error == "No function requester set") {
            std::cerr << "Not connected to server\n";
        } else if (error == "Failed to receive function from server") {
            std::cerr << "Network error or function not available\n";
        } else {
            std::cerr << "Unknown error: " << error << "\n";
        }

        return;
    }

    // Use the result
    bool is_debugged = *result;
    std::cout << "Debugger status: " << is_debugged << "\n";
}
```

## Example 3: Function with Multiple Parameters

```cpp
// Define function with parameters
MARKER_DEF(int, calculate_hash)(const char* data, int length, int seed) {
    int hash = seed;
    for (int i = 0; i < length; ++i) {
        hash = hash * 31 + data[i];
    }
    return hash;
}

// Call it
const char* data = "Hello, World!";
auto result = protect::FnProtectGlobal::Call<int>(
    MARKER(calculate_hash),
    data,
    strlen(data),
    42  // seed
);

if (result) {
    int hash = *result;
    std::cout << "Hash: " << hash << "\n";
}
```

## Example 4: Function Returning Structures

```cpp
struct ProcessInfo {
    uint32_t pid;
    uint32_t threads;
    char name[256];
};

MARKER_DEF(ProcessInfo, get_process_info)(uint32_t pid) {
    ProcessInfo info{};
    info.pid = pid;

#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process) {
        // Fill in info...
        CloseHandle(process);
    }
#endif

    return info;
}

// Call it
auto result = protect::FnProtectGlobal::Call<ProcessInfo>(
    MARKER(get_process_info),
    1234
);

if (result) {
    ProcessInfo info = *result;
    std::cout << "Process: " << info.name << " (PID: " << info.pid << ")\n";
}
```

## Example 5: Async Function Calls

```cpp
#include <future>

// Call function asynchronously
std::future<std::expected<bool, std::string_view>> async_security_check() {
    return std::async(std::launch::async, []() {
        return protect::FnProtectGlobal::Call<bool>(
            MARKER(check_debugger_present)
        );
    });
}

int main() {
    // Start multiple async checks
    auto debug_future = async_security_check();

    auto vm_future = std::async(std::launch::async, []() {
        return protect::FnProtectGlobal::Call<bool>(
            MARKER(check_vm_present)
        );
    });

    // Do other work...

    // Get results
    auto debug_result = debug_future.get();
    auto vm_result = vm_future.get();

    if (debug_result && *debug_result) {
        std::cerr << "Debugger detected!\n";
    }

    if (vm_result && *vm_result) {
        std::cerr << "VM detected!\n";
    }
}
```

## Example 6: Caching Check

```cpp
#include "protected_function.hpp"

void cached_vs_uncached() {
    auto& cache = protect::FunctionCache::instance();

    uint32_t hash = MARKER(check_debugger_present).hash;

    if (cache.has(hash)) {
        std::cout << "Function already in cache, will execute immediately\n";
    } else {
        std::cout << "Function not cached, will request from server\n";
    }

    // Call function (will use cache if available)
    auto result = protect::FnProtectGlobal::Call<bool>(
        MARKER(check_debugger_present)
    );

    // Now it's definitely cached
    std::cout << "Function now in cache: " << cache.has(hash) << "\n";
}
```

## Example 7: Manual Cache Management

```cpp
void clear_cache_on_update() {
    auto& cache = protect::FunctionCache::instance();

    // Clear all cached functions
    cache.clear();
    std::cout << "Function cache cleared\n";

    // Next call will re-request from server
    auto result = protect::FnProtectGlobal::Call<bool>(
        MARKER(check_debugger_present)
    );
}
```

## Example 8: Integration with Existing Systems

```cpp
class SecurityManager {
    bool initialized_ = false;
    bool connection_ok_ = false;

public:
    bool initialize(GameClient* client) {
        if (initialized_) return true;

        // Set function requester
        protect::FnProtectGlobal::set_requester(client);

        // Pre-load critical functions
        std::cout << "Pre-loading security functions...\n";

        auto debug_check = protect::FnProtectGlobal::Call<bool>(
            MARKER(check_debugger_present)
        );

        auto vm_check = protect::FnProtectGlobal::Call<bool>(
            MARKER(check_vm_present)
        );

        if (!debug_check || !vm_check) {
            std::cerr << "Failed to load security functions\n";
            return false;
        }

        initialized_ = true;
        connection_ok_ = true;
        return true;
    }

    bool perform_checks() {
        if (!initialized_ || !connection_ok_) {
            return false;
        }

        // All functions are cached, no network delay
        auto debug = protect::FnProtectGlobal::Call<bool>(
            MARKER(check_debugger_present)
        );

        auto vm = protect::FnProtectGlobal::Call<bool>(
            MARKER(check_vm_present)
        );

        return debug && vm && !(*debug) && !(*vm);
    }
};

int main() {
    GameClient client;
    SecurityManager security;

    if (!client.connect("127.0.0.1", 8888)) {
        return 1;
    }

    if (!security.initialize(&client)) {
        return 1;
    }

    // Main loop
    while (true) {
        if (!security.perform_checks()) {
            std::cerr << "Security violation detected!\n";
            break;
        }

        // Normal operation...
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
```

## Example 9: Timeout Handling

```cpp
// The default timeout is 5 seconds, defined in protected_function.cpp
// To handle timeouts gracefully:

bool wait_for_function_with_retry(int max_retries = 3) {
    for (int i = 0; i < max_retries; ++i) {
        auto result = protect::FnProtectGlobal::Call<bool>(
            MARKER(check_debugger_present)
        );

        if (result) {
            // Success
            return *result;
        }

        // Failed - could be timeout or network error
        std::cerr << "Attempt " << (i + 1) << " failed: "
                  << result.error() << "\n";

        // Wait before retry
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    std::cerr << "All retries failed\n";
    return false;
}
```

## Best Practices

### 1. Pre-load Functions
Load security-critical functions during initialization:
```cpp
void preload_critical_functions() {
    // Load all security functions once at startup
    protect::FnProtectGlobal::Call<bool>(MARKER(check_debugger_present));
    protect::FnProtectGlobal::Call<bool>(MARKER(check_vm_present));
    // Now they're cached for instant access
}
```

### 2. Handle Errors Gracefully
Always check `std::expected` return values:
```cpp
auto result = protect::FnProtectGlobal::Call<bool>(MARKER(my_function));
if (!result) {
    // Handle error - maybe log, retry, or use fallback
    return false;
}
// Use *result
```

### 3. Use Meaningful Names
Function names should be descriptive:
```cpp
// Good
MARKER_DEF(bool, check_debugger_present)() { ... }

// Bad
MARKER_DEF(bool, func1)() { ... }
```

### 4. Keep Functions Small
Limit function size to stay under 4KB payload:
```cpp
// Good: Small, focused function
MARKER_DEF(bool, is_debugged)() {
    return IsDebuggerPresent();
}

// Bad: Large function with many operations
MARKER_DEF(void, do_everything)() {
    // Thousands of lines...
}
```

### 5. Avoid Global State
Protected functions should be self-contained:
```cpp
// Good: All data passed as parameters
MARKER_DEF(int, hash_data)(const char* data, int len) {
    // Pure function
}

// Bad: Relies on global state
static int global_value;
MARKER_DEF(int, bad_function)() {
    return global_value;  // Won't work correctly
}
```

### 6. Platform-Specific Code
Always guard platform-specific code:
```cpp
MARKER_DEF(bool, platform_specific)() {
#ifdef _WIN32
    // Windows implementation
    return true;
#elif defined(__linux__)
    // Linux implementation
    return true;
#else
    // Not supported
    return false;
#endif
}
```
