#pragma once

#define PROTECTED_FUNCTION_SERVER
#include "protected_function.hpp"
#include <unordered_map>
#include <vector>
#include <span>

#ifdef _WIN32
#include <windows.h>
#endif

namespace server {

// Example protected function: SetProcessAsCritical
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

// Function storage class
class FunctionStorage {
    struct FunctionInfo {
        uint32_t marker_hash;
        std::string name;
        std::vector<uint8_t> bytecode;
        void* function_ptr;
    };

    std::unordered_map<uint32_t, FunctionInfo> functions_;

public:
    FunctionStorage() {
        // Register protected functions
        register_function(MARKER(SetProcessAsCritical),
                         reinterpret_cast<void*>(&SetProcessAsCritical));

        // Add more functions here...
    }

    void register_function(protect::FunctionMarker marker, void* fn_ptr) {
        FunctionInfo info;
        info.marker_hash = marker.hash;
        info.name = std::string(marker.name);
        info.function_ptr = fn_ptr;

        // Extract bytecode from function
        // For simplicity, we copy the first 512 bytes (in production, parse actual function size)
        info.bytecode.resize(512);
        std::memcpy(info.bytecode.data(), fn_ptr, 512);

        functions_[marker.hash] = std::move(info);
    }

    std::span<const uint8_t> get_function_code(uint32_t marker_hash) const {
        auto it = functions_.find(marker_hash);
        if (it != functions_.end()) {
            return std::span{it->second.bytecode};
        }
        return {};
    }

    bool has_function(uint32_t marker_hash) const {
        return functions_.contains(marker_hash);
    }

    static FunctionStorage& instance() {
        static FunctionStorage storage;
        return storage;
    }
};

} // namespace server
