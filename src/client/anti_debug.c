#include "anti_debug.h"

#ifdef _WIN32

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

/* Vérifie si un debugger est attaché */
uint8_t is_debugger_present(void) {
    /* Méthode 1: IsDebuggerPresent() */
    if (IsDebuggerPresent()) {
        return 1;
    }

    /* Méthode 2: PEB (Process Environment Block) */
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    if (isDebugged) {
        return 1;
    }

    /* Méthode 3: NtQueryInformationProcess */
    typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
    );

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
            GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (NtQIP) {
            DWORD debugPort = 0;
            NTSTATUS status = NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (status == 0 && debugPort != 0) {
                return 1;
            }
        }
    }

    return 0;
}

/* Vérifie si on tourne dans une VM */
uint8_t is_virtual_machine(void) {
    /* Méthode 1: Vérifier les chaînes de registre */
    HKEY hKey;
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);

    /* Vérifier BIOS */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DESCRIPTION\\System\\BIOS",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL,
                            (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            /* VMware, VirtualBox, QEMU, Hyper-V, etc. */
            if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") ||
                strstr(buffer, "QEMU") || strstr(buffer, "Microsoft") ||
                strstr(buffer, "Xen")) {
                RegCloseKey(hKey);
                return 1;
            }
        }
        RegCloseKey(hKey);
    }

    /* Méthode 2: Instruction CPUID pour détecter hyperviseur */
    #if defined(_M_X64) || defined(__x86_64__)
    int cpuInfo[4] = {0};
    #ifdef _MSC_VER
    __cpuid(cpuInfo, 1);
    #else
    __asm__ __volatile__(
        "cpuid"
        : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
        : "a"(1)
    );
    #endif
    /* Bit 31 de ECX indique présence hyperviseur */
    if (cpuInfo[2] & (1 << 31)) {
        return 1;
    }
    #endif

    /* Méthode 3: Vérifier le nombre de processeurs */
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        /* Souvent signe de VM avec peu de ressources */
        return 1;
    }

    /* Méthode 4: Vérifier la mémoire physique */
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    /* Moins de 2GB de RAM = suspect */
    if (memStatus.ullTotalPhys < 2147483648ULL) {
        return 1;
    }

    return 0;
}

/* Vérifie si le processus est suspendu */
uint8_t is_process_suspended(void) {
    /* Vérifier si tous les threads sont suspendus */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    DWORD currentPid = GetCurrentProcessId();
    uint32_t totalThreads = 0;
    uint32_t suspendedThreads = 0;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentPid) {
                totalThreads++;

                /* Ouvrir le thread pour vérifier son état */
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    /* Utiliser NtQueryInformationThread pour obtenir l'état */
                    typedef NTSTATUS (WINAPI *pNtQueryInformationThread)(
                        HANDLE ThreadHandle,
                        DWORD ThreadInformationClass,
                        PVOID ThreadInformation,
                        ULONG ThreadInformationLength,
                        PULONG ReturnLength
                    );

                    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                    if (hNtdll) {
                        pNtQueryInformationThread NtQIT = (pNtQueryInformationThread)
                            GetProcAddress(hNtdll, "NtQueryInformationThread");

                        if (NtQIT) {
                            ULONG state = 0;
                            NTSTATUS status = NtQIT(hThread, 0, &state, sizeof(state), NULL);
                            /* 5 = Suspended */
                            if (status == 0 && state == 5) {
                                suspendedThreads++;
                            }
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    /* Si plus de 50% des threads sont suspendus */
    if (totalThreads > 0 && suspendedThreads >= (totalThreads / 2)) {
        return 1;
    }

    return 0;
}

#endif /* _WIN32 */
