#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <stdint.h>

#ifdef _WIN32
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

/* Shellcode pour syscall direct (x64) */
typedef struct {
    uint8_t shellcode[13];  /* mov r10,rcx; mov rax,SSN; syscall; ret */
    void* exec_memory;      /* Mémoire RWX allouée */
    uint32_t ssn;           /* System Service Number */
    uint8_t initialized;
} syscall_stub_t;

/* Cache pour les SSN */
typedef struct {
    const char* name;
    uint32_t ssn;
} ssn_cache_entry_t;

#define MAX_SSN_CACHE 32

/* Fonctions d'initialisation */
int syscalls_init(void);
void syscalls_cleanup(void);

/* API bas niveau : préparer un stub syscall */
int syscall_prepare(syscall_stub_t* stub, const char* function_name);
void syscall_cleanup_stub(syscall_stub_t* stub);

/* Wrappers haut niveau pour les syscalls courants */
NTSTATUS nt_allocate_virtual_memory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS nt_write_virtual_memory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS nt_protect_virtual_memory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

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
    PVOID AttributeList
);

NTSTATUS nt_open_process(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

NTSTATUS nt_close(HANDLE Handle);

/* Macros pour vérifier les NTSTATUS */
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#endif /* _WIN32 */

#endif /* SYSCALLS_H */
