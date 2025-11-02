#pragma once

#ifdef _WIN32

#include <windows.h>
#include <array>
#include <concepts>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <format>

namespace shadow {

// Concepts
template<typename T>
concept NtHandle = std::same_as<T, HANDLE> || std::same_as<T, void*>;

template<typename T>
concept NtStatus = std::same_as<T, long>;

// NT Structures
struct UniqueProcess { HANDLE value; };
struct UniqueThread  { HANDLE value; };

struct ClientId {
    UniqueProcess process;
    UniqueThread thread;
};

struct ObjectAttributes {
    ULONG length = sizeof(ObjectAttributes);
    HANDLE root_directory = nullptr;
    void* object_name = nullptr;
    ULONG attributes = 0;
    void* security_descriptor = nullptr;
    void* security_qos = nullptr;
};

// RAII Wrapper pour les handles NT
class NtHandleGuard {
    HANDLE handle_ = nullptr;

public:
    explicit NtHandleGuard(HANDLE h = nullptr) : handle_(h) {}
    ~NtHandleGuard();

    NtHandleGuard(const NtHandleGuard&) = delete;
    NtHandleGuard& operator=(const NtHandleGuard&) = delete;

    NtHandleGuard(NtHandleGuard&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    NtHandleGuard& operator=(NtHandleGuard&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] HANDLE release() noexcept {
        auto h = handle_;
        handle_ = nullptr;
        return h;
    }

    void reset(HANDLE h = nullptr);
    [[nodiscard]] explicit operator bool() const noexcept { return handle_ != nullptr; }
};

// Shellcode stub avec RAII
class SyscallStub {
    static constexpr std::array<uint8_t, 13> kTemplate = {
        0x49, 0x89, 0xCA,                          // mov r10, rcx
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, SSN
        0x0F, 0x05,                                // syscall
        0xC3                                       // ret
    };

    void* exec_memory_ = nullptr;
    uint32_t ssn_ = 0;

public:
    explicit SyscallStub(std::string_view function_name);
    ~SyscallStub();

    SyscallStub(const SyscallStub&) = delete;
    SyscallStub& operator=(const SyscallStub&) = delete;

    SyscallStub(SyscallStub&& other) noexcept
        : exec_memory_(other.exec_memory_), ssn_(other.ssn_) {
        other.exec_memory_ = nullptr;
    }

    template<typename Ret, typename... Args>
    Ret invoke(Args&&... args) const noexcept {
        using FnPtr = Ret(__stdcall*)(Args...);
        return reinterpret_cast<FnPtr>(exec_memory_)(std::forward<Args>(args)...);
    }

    [[nodiscard]] bool valid() const noexcept { return exec_memory_ != nullptr; }
    [[nodiscard]] uint32_t ssn() const noexcept { return ssn_; }
};

// Cache SSN singleton
class SsnCache {
    std::unordered_map<std::string_view, uint32_t> cache_;

    SsnCache() = default;

public:
    static SsnCache& instance() {
        static SsnCache cache;
        return cache;
    }

    std::expected<uint32_t, std::string_view> lookup(std::string_view name);
    void insert(std::string_view name, uint32_t ssn) { cache_[name] = ssn; }
};

// Syscall Manager
class SyscallManager {
    std::unique_ptr<SyscallStub> alloc_vm_;
    std::unique_ptr<SyscallStub> write_vm_;
    std::unique_ptr<SyscallStub> protect_vm_;
    std::unique_ptr<SyscallStub> create_thread_;
    std::unique_ptr<SyscallStub> open_process_;
    std::unique_ptr<SyscallStub> close_;

    SyscallManager();

public:
    static SyscallManager& instance() {
        static SyscallManager mgr;
        return mgr;
    }

    // Modern API avec std::expected
    std::expected<void*, long> allocate_memory(
        HANDLE process,
        void* base,
        size_t size,
        uint32_t alloc_type,
        uint32_t protect
    ) const noexcept;

    std::expected<size_t, long> write_memory(
        HANDLE process,
        void* base,
        std::span<const uint8_t> data
    ) const noexcept;

    std::expected<uint32_t, long> protect_memory(
        HANDLE process,
        void* base,
        size_t size,
        uint32_t new_protect
    ) const noexcept;

    std::expected<NtHandleGuard, long> create_thread(
        HANDLE process,
        void* start_routine,
        void* parameter
    ) const noexcept;

    std::expected<NtHandleGuard, long> open_process(
        uint32_t pid,
        uint32_t access = PROCESS_ALL_ACCESS
    ) const noexcept;
};

// Helper pour extraire SSN
std::expected<uint32_t, std::string_view> extract_ssn(void* function_address) noexcept;

} // namespace shadow

#endif // _WIN32
