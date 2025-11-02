#pragma once

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string_view>
#include <functional>
#include <unordered_map>
#include <expected>
#include <span>
#include <memory>
#include <mutex>
#include <condition_variable>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace protect {

// Compile-time hash for function markers
constexpr uint32_t fnv1a_hash(std::string_view str) noexcept {
    uint32_t hash = 2166136261u;
    for (char c : str) {
        hash ^= static_cast<uint32_t>(c);
        hash *= 16777619u;
    }
    return hash;
}

// Marker type - identifies a protected function
struct FunctionMarker {
    uint32_t hash;
    std::string_view name;

    constexpr FunctionMarker(std::string_view n) noexcept
        : hash(fnv1a_hash(n)), name(n) {}

    // Compare both hash AND name to prevent collision attacks
    constexpr bool operator==(const FunctionMarker& other) const noexcept {
        return hash == other.hash && name == other.name;
    }
};

// Macro to create a marker
#define MARKER(name) ::protect::FunctionMarker{#name}

// Macro to define a protected function (stub on client, real on server)
#ifdef PROTECTED_FUNCTION_SERVER
    // Server side: real implementation
    #define MARKER_DEF(RetType, Name) \
        static RetType Name
#else
    // Client side: stub that will request from server
    #define MARKER_DEF(RetType, Name) \
        static RetType Name [[maybe_unused]]
#endif

// Temporary function executor - allocates executable memory, executes, then immediately frees
// Supports W^X systems (SELinux, hardened Linux) by using RW -> RX transition
// This prevents the function from staying in memory for analysis
class TemporaryFunction {
    void* exec_memory_ = nullptr;
    size_t size_ = 0;
    bool using_wx_separate_ = false;

public:
    explicit TemporaryFunction(std::span<const uint8_t> bytecode) : size_(bytecode.size()) {
        if (bytecode.empty()) return;

#ifdef _WIN32
        // Try RWX first (most common)
        exec_memory_ = VirtualAlloc(nullptr, size_,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);

        if (!exec_memory_) {
            // If RWX fails (rare on Windows), try RW -> RX
            exec_memory_ = VirtualAlloc(nullptr, size_,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
            using_wx_separate_ = true;
        }

        if (exec_memory_) {
            std::memcpy(exec_memory_, bytecode.data(), size_);

            // If using W^X, change to RX now
            if (using_wx_separate_) {
                DWORD old_protect;
                VirtualProtect(exec_memory_, size_, PAGE_EXECUTE_READ, &old_protect);
            }
        }
#else
        // Try RWX first
        exec_memory_ = mmap(nullptr, size_,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (exec_memory_ == MAP_FAILED) {
            // W^X enforcement - try RW -> RX
            exec_memory_ = mmap(nullptr, size_,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            using_wx_separate_ = true;
        }

        if (exec_memory_ != MAP_FAILED) {
            std::memcpy(exec_memory_, bytecode.data(), size_);

            // Flush instruction cache and change to RX
            if (using_wx_separate_) {
                __builtin___clear_cache(
                    reinterpret_cast<char*>(exec_memory_),
                    reinterpret_cast<char*>(exec_memory_) + size_
                );
                mprotect(exec_memory_, size_, PROT_READ | PROT_EXEC);
            }
        } else {
            exec_memory_ = nullptr;
        }
#endif
    }

    ~TemporaryFunction() {
        // Immediately free executable memory after use
        if (exec_memory_) {
#ifdef _WIN32
            VirtualFree(exec_memory_, 0, MEM_RELEASE);
#else
            munmap(exec_memory_, size_);
#endif
            exec_memory_ = nullptr;
        }
    }

    TemporaryFunction(const TemporaryFunction&) = delete;
    TemporaryFunction& operator=(const TemporaryFunction&) = delete;
    TemporaryFunction(TemporaryFunction&&) = delete;

    template<typename Ret, typename... Args>
    Ret execute(Args&&... args) const {
        if (!exec_memory_) {
            if constexpr (std::is_same_v<Ret, bool>) {
                return false;
            } else if constexpr (std::is_arithmetic_v<Ret>) {
                return static_cast<Ret>(0);
            } else {
                return Ret{};
            }
        }

        using FnPtr = Ret(*)(Args...);
        auto fn = reinterpret_cast<FnPtr>(exec_memory_);
        return fn(std::forward<Args>(args)...);
    }

    [[nodiscard]] bool valid() const noexcept {
        return exec_memory_ != nullptr;
    }
};

// Simple SHA256 implementation for bytecode integrity verification
inline constexpr uint32_t simple_checksum(std::span<const uint8_t> data) noexcept {
    uint32_t checksum = 0x5A5A5A5A;
    for (size_t i = 0; i < data.size(); ++i) {
        checksum ^= data[i];
        checksum = (checksum << 7) | (checksum >> 25);
        checksum += i * 0x01000193;
    }
    return checksum;
}

// Bytecode storage - stores raw bytes with integrity verification
// RWX memory is allocated only during execution and freed immediately after
class BytecodeStorage {
    struct BytecodeEntry {
        std::string name;
        std::vector<uint8_t> code;
        uint32_t checksum;
        size_t expected_size;
    };

    std::unordered_map<uint32_t, BytecodeEntry> storage_;
    std::mutex mutex_;

    BytecodeStorage() = default;

public:
    static BytecodeStorage& instance() {
        static BytecodeStorage storage;
        return storage;
    }

    // Store bytecode with name verification and integrity check
    bool store(uint32_t marker_hash, std::string_view name, std::span<const uint8_t> code) {
        std::lock_guard lock(mutex_);

        // Detect hash collision - different name with same hash
        auto it = storage_.find(marker_hash);
        if (it != storage_.end() && it->second.name != name) {
            // CRITICAL: Hash collision detected!
            return false;
        }

        BytecodeEntry entry;
        entry.name = std::string(name);
        entry.code = std::vector<uint8_t>(code.begin(), code.end());
        entry.checksum = simple_checksum(code);
        entry.expected_size = code.size();

        storage_[marker_hash] = std::move(entry);
        return true;
    }

    // Get bytecode with integrity verification
    std::vector<uint8_t> get(uint32_t marker_hash, std::string_view expected_name) {
        std::lock_guard lock(mutex_);
        auto it = storage_.find(marker_hash);

        if (it == storage_.end()) {
            return {};
        }

        auto& entry = it->second;

        // Verify name matches (collision detection)
        if (entry.name != expected_name) {
            return {};
        }

        // Verify integrity
        uint32_t actual_checksum = simple_checksum(entry.code);
        if (actual_checksum != entry.checksum) {
            // Bytecode corrupted!
            storage_.erase(it);
            return {};
        }

        // Verify size
        if (entry.code.size() != entry.expected_size) {
            // Size mismatch!
            storage_.erase(it);
            return {};
        }

        return entry.code;
    }

    bool has(uint32_t marker_hash, std::string_view expected_name) {
        std::lock_guard lock(mutex_);
        auto it = storage_.find(marker_hash);
        return it != storage_.end() && it->second.name == expected_name;
    }

    void clear() {
        std::lock_guard lock(mutex_);
        storage_.clear();
    }
};

// Pending function requests
class PendingRequests {
    struct Request {
        uint32_t marker_hash;
        std::mutex mutex;
        std::condition_variable cv;
        bool completed = false;
    };

    std::unordered_map<uint32_t, std::shared_ptr<Request>> requests_;
    std::mutex mutex_;

    PendingRequests() = default;

public:
    static PendingRequests& instance() {
        static PendingRequests pending;
        return pending;
    }

    std::shared_ptr<Request> add(uint32_t marker_hash) {
        std::lock_guard lock(mutex_);
        auto req = std::make_shared<Request>();
        req->marker_hash = marker_hash;
        requests_[marker_hash] = req;
        return req;
    }

    void complete(uint32_t marker_hash) {
        std::shared_ptr<Request> req;
        {
            std::lock_guard lock(mutex_);
            auto it = requests_.find(marker_hash);
            if (it != requests_.end()) {
                req = it->second;
                requests_.erase(it);
            }
        }

        if (req) {
            std::lock_guard lock(req->mutex);
            req->completed = true;
            req->cv.notify_all();
        }
    }

    // Remove a pending request (e.g., on immediate send failure)
    void remove(uint32_t marker_hash) {
        std::lock_guard lock(mutex_);
        requests_.erase(marker_hash);
    }

    bool wait_for(uint32_t marker_hash, std::chrono::milliseconds timeout) {
        std::shared_ptr<Request> req;
        {
            std::lock_guard lock(mutex_);
            auto it = requests_.find(marker_hash);
            if (it != requests_.end()) {
                req = it->second;
            }
        }

        if (!req) return false;

        std::unique_lock lock(req->mutex);
        bool success = req->cv.wait_for(lock, timeout, [&] { return req->completed; });

        // CRITICAL: Clean up request from map regardless of success/failure
        // This prevents memory leaks and allows retries
        {
            std::lock_guard map_lock(mutex_);
            auto it = requests_.find(marker_hash);
            if (it != requests_.end() && !it->second->completed) {
                // Only remove if not completed (complete() already removed it)
                requests_.erase(it);
            }
        }

        return success;
    }
};

// Forward declaration for client communication
class FunctionRequester;

// Global protected function caller
class FnProtectGlobal {
    static inline FunctionRequester* requester_ = nullptr;

public:
    static void set_requester(FunctionRequester* req) {
        requester_ = req;
    }

    template<typename Ret, typename... Args>
    static std::expected<Ret, std::string_view> Call(
        FunctionMarker marker, Args&&... args
    ) {
        auto& storage = BytecodeStorage::instance();

        // Check if bytecode is in storage (with name verification)
        std::vector<uint8_t> bytecode = storage.get(marker.hash, marker.name);

        // If not in storage, request from server
        if (bytecode.empty()) {
            if (!requester_) {
                return std::unexpected("No function requester set");
            }

            // Request function and wait for response
            if (!request_and_wait(marker.hash)) {
                return std::unexpected("Failed to receive function from server");
            }

            // Get bytecode from storage with verification
            bytecode = storage.get(marker.hash, marker.name);
            if (bytecode.empty()) {
                return std::unexpected("Function bytecode not available or integrity check failed");
            }
        }

        // Additional size sanity check
        if (bytecode.size() > 1024 * 1024) {  // 1MB max
            return std::unexpected("Function bytecode too large - possible corruption");
        }

        if (bytecode.size() < 4) {  // Minimum viable function size
            return std::unexpected("Function bytecode too small - possible corruption");
        }

        // Allocate executable memory temporarily (RAII - freed on scope exit)
        // Supports both RWX and W^X systems
        TemporaryFunction temp_fn(bytecode);

        if (!temp_fn.valid()) {
            return std::unexpected("Failed to allocate executable memory (W^X or SELinux may be blocking)");
        }

        // Execute function - memory will be freed automatically when temp_fn goes out of scope
        return temp_fn.execute<Ret>(std::forward<Args>(args)...);
    }

private:
    static bool request_and_wait(uint32_t marker_hash);
};

// Function requester interface (implemented by client)
class FunctionRequester {
public:
    virtual ~FunctionRequester() = default;
    virtual bool request_function(uint32_t marker_hash) = 0;
};

} // namespace protect
