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

    constexpr bool operator==(const FunctionMarker& other) const noexcept {
        return hash == other.hash;
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

// Function bytecode wrapper
struct FunctionCode {
    std::vector<uint8_t> code;
    size_t code_size = 0;
    void* exec_memory = nullptr;

    FunctionCode() = default;

    explicit FunctionCode(std::span<const uint8_t> bytes)
        : code(bytes.begin(), bytes.end()), code_size(bytes.size()) {
        allocate_executable();
    }

    ~FunctionCode() {
        if (exec_memory) {
#ifdef _WIN32
            VirtualFree(exec_memory, 0, MEM_RELEASE);
#else
            munmap(exec_memory, code_size);
#endif
        }
    }

    FunctionCode(const FunctionCode&) = delete;
    FunctionCode& operator=(const FunctionCode&) = delete;

    FunctionCode(FunctionCode&& other) noexcept
        : code(std::move(other.code))
        , code_size(other.code_size)
        , exec_memory(other.exec_memory) {
        other.exec_memory = nullptr;
    }

    void allocate_executable() {
        if (code.empty()) return;

#ifdef _WIN32
        exec_memory = VirtualAlloc(nullptr, code.size(),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
        if (exec_memory) {
            std::memcpy(exec_memory, code.data(), code.size());
        }
#else
        exec_memory = mmap(nullptr, code.size(),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_memory != MAP_FAILED) {
            std::memcpy(exec_memory, code.data(), code.size());
        } else {
            exec_memory = nullptr;
        }
#endif
    }

    template<typename Ret, typename... Args>
    Ret invoke(Args&&... args) const {
        using FnPtr = Ret(*)(Args...);
        auto fn = reinterpret_cast<FnPtr>(exec_memory);
        return fn(std::forward<Args>(args)...);
    }

    [[nodiscard]] bool valid() const noexcept {
        return exec_memory != nullptr;
    }
};

// Function cache
class FunctionCache {
    std::unordered_map<uint32_t, std::unique_ptr<FunctionCode>> cache_;
    std::mutex mutex_;

    FunctionCache() = default;

public:
    static FunctionCache& instance() {
        static FunctionCache cache;
        return cache;
    }

    void store(uint32_t marker_hash, std::span<const uint8_t> code) {
        std::lock_guard lock(mutex_);
        cache_[marker_hash] = std::make_unique<FunctionCode>(code);
    }

    FunctionCode* get(uint32_t marker_hash) {
        std::lock_guard lock(mutex_);
        auto it = cache_.find(marker_hash);
        return it != cache_.end() ? it->second.get() : nullptr;
    }

    bool has(uint32_t marker_hash) {
        std::lock_guard lock(mutex_);
        return cache_.contains(marker_hash);
    }

    void clear() {
        std::lock_guard lock(mutex_);
        cache_.clear();
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
        return req->cv.wait_for(lock, timeout, [&] { return req->completed; });
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
        auto& cache = FunctionCache::instance();

        // Check if function is already in cache
        if (auto* fn_code = cache.get(marker.hash)) {
            if (fn_code->valid()) {
                return fn_code->invoke<Ret>(std::forward<Args>(args)...);
            }
        }

        // Function not in cache, request from server
        if (!requester_) {
            return std::unexpected("No function requester set");
        }

        // Request function and wait for response
        if (!request_and_wait(marker.hash)) {
            return std::unexpected("Failed to receive function from server");
        }

        // Try again from cache
        if (auto* fn_code = cache.get(marker.hash)) {
            if (fn_code->valid()) {
                return fn_code->invoke<Ret>(std::forward<Args>(args)...);
            }
        }

        return std::unexpected("Function execution failed");
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
