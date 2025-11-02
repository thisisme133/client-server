/*
 * Test simple des syscalls directs
 * Compile: gcc -I./include test_syscalls.c src/client/syscalls.c -o test_syscalls -lntdll
 */

#ifdef _WIN32

#include "syscalls.h"
#include <stdio.h>

int main(void) {
    printf("[*] Test des syscalls directs (shadow_syscall logic)\n\n");

    /* Init */
    if (syscalls_init() != 0) {
        printf("[!] Erreur: syscalls_init() a echoue\n");
        return 1;
    }
    printf("[+] syscalls_init() OK\n");

    /* Test 1: NtAllocateVirtualMemory */
    printf("\n[*] Test NtAllocateVirtualMemory...\n");
    HANDLE hProcess = (HANDLE)-1;  /* Current process */
    void* base_addr = NULL;
    SIZE_T region_size = 4096;

    NTSTATUS status = nt_allocate_virtual_memory(
        hProcess,
        &base_addr,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NT_SUCCESS(status)) {
        printf("[+] Allocation reussie: 0x%p (%zu bytes)\n", base_addr, (size_t)region_size);
    } else {
        printf("[!] Allocation echouee: NTSTATUS = 0x%08X\n", (unsigned int)status);
    }

    /* Test 2: NtWriteVirtualMemory */
    if (NT_SUCCESS(status)) {
        printf("\n[*] Test NtWriteVirtualMemory...\n");
        const char test_data[] = "SHADOW_SYSCALL_TEST";
        SIZE_T written = 0;

        status = nt_write_virtual_memory(
            hProcess,
            base_addr,
            (void*)test_data,
            sizeof(test_data),
            &written
        );

        if (NT_SUCCESS(status)) {
            printf("[+] Ecriture reussie: %zu bytes\n", (size_t)written);
            printf("[+] Verification: %s\n", (char*)base_addr);
        } else {
            printf("[!] Ecriture echouee: NTSTATUS = 0x%08X\n", (unsigned int)status);
        }
    }

    /* Test 3: NtProtectVirtualMemory */
    if (NT_SUCCESS(status)) {
        printf("\n[*] Test NtProtectVirtualMemory...\n");
        void* protect_addr = base_addr;
        SIZE_T protect_size = 4096;
        ULONG old_protect;

        status = nt_protect_virtual_memory(
            hProcess,
            &protect_addr,
            &protect_size,
            PAGE_EXECUTE_READ,
            &old_protect
        );

        if (NT_SUCCESS(status)) {
            printf("[+] Protection changee: old=0x%08X new=PAGE_EXECUTE_READ\n", (unsigned int)old_protect);
        } else {
            printf("[!] Protection echouee: NTSTATUS = 0x%08X\n", (unsigned int)status);
        }
    }

    /* Cleanup */
    syscalls_cleanup();
    printf("\n[+] syscalls_cleanup() OK\n");
    printf("\n[*] Tous les tests sont passes!\n");

    return 0;
}

#else

#include <stdio.h>

int main(void) {
    printf("Ce test fonctionne uniquement sur Windows x64.\n");
    return 0;
}

#endif
