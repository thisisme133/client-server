#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <stdint.h>
#include <windows.h>

/* Structures NT natives */
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* Protection flags */
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80

/* Memory allocation types */
#define MEM_COMMIT             0x1000
#define MEM_RESERVE            0x2000
#define MEM_RELEASE            0x8000

/* Access rights */
#define PROCESS_ALL_ACCESS     0x1F0FFF
#define THREAD_ALL_ACCESS      0x1F03FF

/* Syscall numbers (Windows 10 x64) */
typedef struct {
    uint16_t NtAllocateVirtualMemory;
    uint16_t NtWriteVirtualMemory;
    uint16_t NtProtectVirtualMemory;
    uint16_t NtCreateThreadEx;
    uint16_t NtOpenProcess;
    uint16_t NtClose;
} syscall_table_t;

/* Global syscall table */
extern syscall_table_t g_syscall_table;

/* Fonctions d'initialisation */
int syscalls_init(void);
void syscalls_cleanup(void);

/* Wrappers des syscalls directs */
NTSTATUS syscall_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS syscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

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
    PVOID AttributeList
);

NTSTATUS syscall_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

NTSTATUS syscall_NtClose(
    HANDLE Handle
);

/* Macros pour vérifier les NTSTATUS */
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#endif /* SYSCALLS_H */
