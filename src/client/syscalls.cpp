#include "syscalls.hpp"
#include <algorithm>
#include <ranges>

#ifdef _WIN32

namespace shadow {

namespace {
    constexpr std::array<uint8_t, 7> kSyscallPattern = {
        0x4C, 0x8B, 0xD1,  // mov r10, rcx
        0xB8,              // mov eax, SSN
        0x00,              // padding
        0x00,              // padding
        0x00               // padding
    };
}

// Extract SSN from NT function prologue
std::expected<uint32_t, std::string_view> extract_ssn(void* function_address) noexcept {
    if (!function_address) return std::unexpected("Null function address");

    // TODO: Add hook detection before SSN extraction:
    //  - Check for JMP/CALL instructions at function start
    //  - Verify expected NT function prologue
    //  - Detect inline hooks and trampolines
    //
    // TODO: Add alternative SSN extraction methods:
    //  - Parse SSDT (System Service Descriptor Table)
    //  - Use neighboring functions for SSN calculation
    //  - Implement Hell's Gate / Halo's Gate techniques
    //
    // TODO: Add verification of extracted SSN:
    //  - Cross-reference with multiple sources
    //  - Validate against known SSN ranges per Windows version

    auto bytes = std::span<const uint8_t>(static_cast<uint8_t*>(function_address), 24);

    for (size_t i = 0; i + 7 < bytes.size(); ++i) {
        if (bytes[i] == 0x4C && bytes[i+1] == 0x8B && bytes[i+2] == 0xD1 &&
            bytes[i+3] == 0xB8 && bytes[i+6] == 0x00 && bytes[i+7] == 0x00) {

            uint32_t ssn;
            std::memcpy(&ssn, &bytes[i + 4], sizeof(ssn));
            return ssn;
        }
    }

    return std::unexpected("SSN pattern not found");
}

// SSN Cache
std::expected<uint32_t, std::string_view> SsnCache::lookup(std::string_view name) {
    if (auto it = cache_.find(name); it != cache_.end()) {
        return it->second;
    }

    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return std::unexpected("ntdll.dll not found");

    auto func = GetProcAddress(ntdll, name.data());
    if (!func) return std::unexpected("Function not found");

    auto ssn_result = extract_ssn(func);
    if (!ssn_result) return std::unexpected(ssn_result.error());

    cache_[name] = *ssn_result;
    return *ssn_result;
}

// Syscall Stub
SyscallStub::SyscallStub(std::string_view function_name) {
    auto ssn_result = SsnCache::instance().lookup(function_name);
    if (!ssn_result) return;

    ssn_ = *ssn_result;

    exec_memory_ = VirtualAlloc(nullptr, 13, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_memory_) return;

    auto shellcode = kTemplate;
    std::memcpy(&shellcode[6], &ssn_, sizeof(ssn_));
    std::memcpy(exec_memory_, shellcode.data(), shellcode.size());
}

SyscallStub::~SyscallStub() {
    if (exec_memory_) {
        VirtualFree(exec_memory_, 0, MEM_RELEASE);
    }
}

// NT Handle Guard
NtHandleGuard::~NtHandleGuard() {
    reset();
}

void NtHandleGuard::reset(HANDLE h) {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
        if (auto& mgr = SyscallManager::instance(); true) {
            // Use NtClose syscall
            using NtClose = long(__stdcall*)(HANDLE);
            // Direct syscall via stub would be here, simplified for now
            CloseHandle(handle_);
        }
    }
    handle_ = h;
}

// Syscall Manager
SyscallManager::SyscallManager()
    : alloc_vm_(std::make_unique<SyscallStub>("NtAllocateVirtualMemory"))
    , write_vm_(std::make_unique<SyscallStub>("NtWriteVirtualMemory"))
    , protect_vm_(std::make_unique<SyscallStub>("NtProtectVirtualMemory"))
    , create_thread_(std::make_unique<SyscallStub>("NtCreateThreadEx"))
    , open_process_(std::make_unique<SyscallStub>("NtOpenProcess"))
    , close_(std::make_unique<SyscallStub>("NtClose"))
    , query_vm_(std::make_unique<SyscallStub>("NtQueryVirtualMemory"))
    , free_vm_(std::make_unique<SyscallStub>("NtFreeVirtualMemory"))
    , read_vm_(std::make_unique<SyscallStub>("NtReadVirtualMemory"))
    , query_sys_info_(std::make_unique<SyscallStub>("NtQuerySystemInformation"))
    , query_proc_info_(std::make_unique<SyscallStub>("NtQueryInformationProcess"))
    , set_thread_info_(std::make_unique<SyscallStub>("NtSetInformationThread"))
{}

std::expected<void*, long> SyscallManager::allocate_memory(
    HANDLE process, void* base, size_t size, uint32_t alloc_type, uint32_t protect
) const noexcept {
    if (!alloc_vm_->valid()) return std::unexpected(-1L);

    SIZE_T region_size = size;
    auto status = alloc_vm_->invoke<long>(process, &base, 0ULL, &region_size, alloc_type, protect);

    return status >= 0 ? std::expected<void*, long>(base) : std::unexpected(status);
}

std::expected<size_t, long> SyscallManager::write_memory(
    HANDLE process, void* base, std::span<const uint8_t> data
) const noexcept {
    if (!write_vm_->valid()) return std::unexpected(-1L);

    SIZE_T written = 0;
    auto status = write_vm_->invoke<long>(
        process, base, const_cast<uint8_t*>(data.data()), data.size(), &written
    );

    return status >= 0 ? std::expected<size_t, long>(written) : std::unexpected(status);
}

std::expected<uint32_t, long> SyscallManager::protect_memory(
    HANDLE process, void* base, size_t size, uint32_t new_protect
) const noexcept {
    if (!protect_vm_->valid()) return std::unexpected(-1L);

    SIZE_T region_size = size;
    ULONG old_protect = 0;
    auto status = protect_vm_->invoke<long>(process, &base, &region_size, new_protect, &old_protect);

    return status >= 0 ? std::expected<uint32_t, long>(old_protect) : std::unexpected(status);
}

std::expected<NtHandleGuard, long> SyscallManager::create_thread(
    HANDLE process, void* start_routine, void* parameter
) const noexcept {
    if (!create_thread_->valid()) return std::unexpected(-1L);

    HANDLE thread = nullptr;
    auto status = create_thread_->invoke<long>(
        &thread, THREAD_ALL_ACCESS, nullptr, process,
        start_routine, parameter, 0UL, 0ULL, 0ULL, 0ULL, nullptr
    );

    return status >= 0 ? NtHandleGuard(thread) : std::unexpected(status);
}

std::expected<NtHandleGuard, long> SyscallManager::open_process(
    uint32_t pid, uint32_t access
) const noexcept {
    if (!open_process_->valid()) return std::unexpected(-1L);

    HANDLE process = nullptr;
    ClientId cid{ .process = {reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid))}, .thread = {nullptr} };
    ObjectAttributes obj_attr{};

    auto status = open_process_->invoke<long>(&process, access, &obj_attr, &cid);

    return status >= 0 ? NtHandleGuard(process) : std::unexpected(status);
}

std::expected<size_t, long> SyscallManager::read_memory(
    HANDLE process, void* base, std::span<uint8_t> buffer
) const noexcept {
    if (!read_vm_->valid()) return std::unexpected(-1L);

    SIZE_T bytes_read = 0;
    auto status = read_vm_->invoke<long>(
        process, base, buffer.data(), buffer.size(), &bytes_read
    );

    return status >= 0 ? std::expected<size_t, long>(bytes_read) : std::unexpected(status);
}

std::expected<void, long> SyscallManager::free_memory(
    HANDLE process, void* base, size_t size
) const noexcept {
    if (!free_vm_->valid()) return std::unexpected(-1L);

    SIZE_T region_size = size;
    auto status = free_vm_->invoke<long>(process, &base, &region_size, MEM_RELEASE);

    return status >= 0 ? std::expected<void, long>() : std::unexpected(status);
}

std::expected<void, long> SyscallManager::query_virtual_memory(
    HANDLE process, void* base, int info_class, void* info_buffer, size_t info_length, size_t* return_length
) const noexcept {
    if (!query_vm_->valid()) return std::unexpected(-1L);

    SIZE_T ret_len = 0;
    auto status = query_vm_->invoke<long>(
        process, base, info_class, info_buffer, info_length, &ret_len
    );

    if (return_length) *return_length = ret_len;
    return status >= 0 ? std::expected<void, long>() : std::unexpected(status);
}

std::expected<void, long> SyscallManager::query_information_process(
    HANDLE process, int info_class, void* info_buffer, size_t info_length, size_t* return_length
) const noexcept {
    if (!query_proc_info_->valid()) return std::unexpected(-1L);

    ULONG ret_len = 0;
    auto status = query_proc_info_->invoke<long>(
        process, info_class, info_buffer, static_cast<ULONG>(info_length), &ret_len
    );

    if (return_length) *return_length = ret_len;
    return status >= 0 ? std::expected<void, long>() : std::unexpected(status);
}

std::expected<void, long> SyscallManager::set_information_thread(
    HANDLE thread, int info_class, void* info_buffer, size_t info_length
) const noexcept {
    if (!set_thread_info_->valid()) return std::unexpected(-1L);

    auto status = set_thread_info_->invoke<long>(
        thread, info_class, info_buffer, static_cast<ULONG>(info_length)
    );

    return status >= 0 ? std::expected<void, long>() : std::unexpected(status);
}

// SSN Cache refresh and anti-tampering
void SsnCache::refresh_if_needed() {
    // Get current Windows build number
    OSVERSIONINFOEXW osvi{};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    using RtlGetVersion = long(__stdcall*)(OSVERSIONINFOEXW*);
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    auto rtl_get_version = reinterpret_cast<RtlGetVersion>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!rtl_get_version) return;

    rtl_get_version(&osvi);
    uint32_t current_build = osvi.dwBuildNumber;

    // Check if build changed or ntdll base changed
    void* current_ntdll = ntdll;
    if (windows_build_ != current_build || ntdll_base_ != current_ntdll) {
        clear();
        windows_build_ = current_build;
        ntdll_base_ = current_ntdll;
    }
}

bool SsnCache::verify_ntdll_integrity() const noexcept {
    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    // Check DOS header
    auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // Check NT headers
    auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(ntdll) + dos_header->e_lfanew
    );
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;

    // Check .text section for hooks (basic check)
    auto section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".text", 5) == 0) {
            auto text_start = reinterpret_cast<uint8_t*>(ntdll) + section->VirtualAddress;
            // Check first bytes for common hook patterns (JMP, CALL)
            if (text_start[0] == 0xE9 || text_start[0] == 0xE8) {
                return false; // Potential hook detected
            }
        }
    }

    return true;
}

} // namespace shadow

#endif // _WIN32
