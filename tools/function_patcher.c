/*
 * Function Patcher Tool
 *
 * Cet outil lit le fichier PDB d'un exécutable, trouve les fonctions
 * marquées comme "protégées", sauvegarde leurs bytes originaux dans
 * des fichiers .bytes, et les remplace par des NOPs dans l'exécutable.
 *
 * Usage: function_patcher.exe client.exe
 */

#ifdef _WIN32

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "dbghelp.lib")

#define MAX_FUNCTIONS 256
#define OUTPUT_DIR "protected_functions"

typedef struct {
    char name[256];
    DWORD rva;              /* Relative Virtual Address */
    DWORD size;
    DWORD file_offset;      /* Offset dans le fichier PE */
} function_info_t;

static function_info_t protected_functions[MAX_FUNCTIONS];
static DWORD protected_function_count = 0;

/* Variables globales pour le symbole handler */
static HANDLE g_process = NULL;
static DWORD64 g_base_address = 0;

/* Callback pour énumérer les symboles */
static BOOL CALLBACK enum_symbols_callback(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext)
{
    (void)UserContext;

    /* Vérifier si le symbole est une fonction et commence par "PROTECTED_" */
    if (pSymInfo->Tag == SymTagFunction) {
        if (strncmp(pSymInfo->Name, "PROTECTED_", 10) == 0) {
            if (protected_function_count < MAX_FUNCTIONS) {
                strncpy(protected_functions[protected_function_count].name,
                        pSymInfo->Name, sizeof(protected_functions[0].name) - 1);

                protected_functions[protected_function_count].rva = (DWORD)(pSymInfo->Address - g_base_address);
                protected_functions[protected_function_count].size = SymbolSize;

                printf("  [%u] Found: %s (RVA: 0x%08X, Size: %u bytes)\n",
                       protected_function_count,
                       pSymInfo->Name,
                       protected_functions[protected_function_count].rva,
                       SymbolSize);

                protected_function_count++;
            }
        }
    }

    return TRUE;
}

/* Convertir RVA en offset de fichier */
static DWORD rva_to_file_offset(HANDLE hFile, DWORD rva) {
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_headers;
    DWORD bytes_read;

    /* Lire DOS header */
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    ReadFile(hFile, &dos_header, sizeof(dos_header), &bytes_read, NULL);

    /* Lire NT headers */
    SetFilePointer(hFile, dos_header.e_lfanew, NULL, FILE_BEGIN);
    ReadFile(hFile, &nt_headers, sizeof(nt_headers), &bytes_read, NULL);

    /* Lire les sections */
    IMAGE_SECTION_HEADER section;
    DWORD section_offset = dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS);

    for (WORD i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
        SetFilePointer(hFile, section_offset + (i * sizeof(section)), NULL, FILE_BEGIN);
        ReadFile(hFile, &section, sizeof(section), &bytes_read, NULL);

        if (rva >= section.VirtualAddress &&
            rva < section.VirtualAddress + section.SizeOfRawData) {
            return section.PointerToRawData + (rva - section.VirtualAddress);
        }
    }

    return 0;
}

/* Créer le dossier de sortie s'il n'existe pas */
static void create_output_directory(void) {
    CreateDirectoryA(OUTPUT_DIR, NULL);
}

/* Sauvegarder les bytes d'une fonction et la NOPer */
static int patch_function(HANDLE hFile, function_info_t* func) {
    DWORD file_offset = rva_to_file_offset(hFile, func->rva);
    if (file_offset == 0) {
        printf("  ✗ Failed to convert RVA to file offset for %s\n", func->name);
        return -1;
    }

    func->file_offset = file_offset;

    printf("  → Patching: %s\n", func->name);
    printf("    RVA: 0x%08X, File offset: 0x%08X, Size: %u bytes\n",
           func->rva, file_offset, func->size);

    /* Allouer buffer pour les bytes originaux */
    uint8_t* original_bytes = (uint8_t*)malloc(func->size);
    if (!original_bytes) {
        printf("  ✗ Memory allocation failed\n");
        return -1;
    }

    /* Lire les bytes originaux */
    DWORD bytes_read;
    SetFilePointer(hFile, file_offset, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, original_bytes, func->size, &bytes_read, NULL) ||
        bytes_read != func->size) {
        printf("  ✗ Failed to read original bytes\n");
        free(original_bytes);
        return -1;
    }

    /* Sauvegarder dans un fichier .bytes */
    char output_path[512];
    snprintf(output_path, sizeof(output_path), "%s/%s.bytes", OUTPUT_DIR, func->name);

    HANDLE hOutput = CreateFileA(output_path, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("  ✗ Failed to create output file: %s\n", output_path);
        free(original_bytes);
        return -1;
    }

    DWORD bytes_written;
    WriteFile(hOutput, original_bytes, func->size, &bytes_written, NULL);
    CloseHandle(hOutput);

    printf("  ✓ Saved original bytes to: %s (%u bytes)\n", output_path, bytes_written);

    /* Créer un buffer de NOPs */
    uint8_t* nop_bytes = (uint8_t*)malloc(func->size);
    memset(nop_bytes, 0x90, func->size);  /* 0x90 = NOP */

    /* Écrire les NOPs dans le fichier */
    SetFilePointer(hFile, file_offset, NULL, FILE_BEGIN);
    if (!WriteFile(hFile, nop_bytes, func->size, &bytes_written, NULL) ||
        bytes_written != func->size) {
        printf("  ✗ Failed to write NOPs\n");
        free(original_bytes);
        free(nop_bytes);
        return -1;
    }

    printf("  ✓ Replaced with NOPs (%u bytes)\n", bytes_written);

    free(original_bytes);
    free(nop_bytes);
    return 0;
}

/* Créer un fichier de métadonnées */
static void create_metadata_file(void) {
    char metadata_path[512];
    snprintf(metadata_path, sizeof(metadata_path), "%s/metadata.txt", OUTPUT_DIR);

    FILE* f = fopen(metadata_path, "w");
    if (!f) {
        printf("✗ Failed to create metadata file\n");
        return;
    }

    fprintf(f, "# Protected Functions Metadata\n");
    fprintf(f, "# Format: name,rva,size,file_offset\n\n");

    for (DWORD i = 0; i < protected_function_count; i++) {
        fprintf(f, "%s,0x%08X,%u,0x%08X\n",
                protected_functions[i].name,
                protected_functions[i].rva,
                protected_functions[i].size,
                protected_functions[i].file_offset);
    }

    fclose(f);
    printf("\n✓ Metadata saved to: %s\n", metadata_path);
}

int main(int argc, char* argv[]) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf("           Function Patcher Tool (PDB-based)\n");
    printf("═══════════════════════════════════════════════════════════\n\n");

    if (argc != 2) {
        printf("Usage: %s <executable.exe>\n", argv[0]);
        printf("\nThis tool will:\n");
        printf("  1. Load the PDB file for the executable\n");
        printf("  2. Find functions marked as PROTECTED_*\n");
        printf("  3. Save original bytes to .bytes files\n");
        printf("  4. Replace functions with NOPs in the executable\n\n");
        return 1;
    }

    const char* exe_path = argv[1];
    printf("→ Target executable: %s\n\n", exe_path);

    /* Initialiser le système de symboles */
    g_process = GetCurrentProcess();

    if (!SymInitialize(g_process, NULL, FALSE)) {
        printf("✗ Failed to initialize symbol handler\n");
        return 1;
    }

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

    /* Charger le module et son PDB */
    printf("→ Loading PDB symbols...\n");
    g_base_address = SymLoadModuleEx(g_process, NULL, exe_path, NULL, 0x10000000, 0, NULL, 0);

    if (g_base_address == 0) {
        printf("✗ Failed to load symbols (Error: %lu)\n", GetLastError());
        printf("  Make sure the PDB file is in the same directory as the executable\n");
        SymCleanup(g_process);
        return 1;
    }

    printf("✓ Symbols loaded at base: 0x%llX\n\n", g_base_address);

    /* Énumérer les symboles */
    printf("→ Searching for protected functions...\n");
    if (!SymEnumSymbols(g_process, g_base_address, "PROTECTED_*", enum_symbols_callback, NULL)) {
        printf("✗ Failed to enumerate symbols (Error: %lu)\n", GetLastError());
        SymCleanup(g_process);
        return 1;
    }

    printf("\n✓ Found %u protected function(s)\n\n", protected_function_count);

    if (protected_function_count == 0) {
        printf("No protected functions found. Make sure to mark functions with PROTECTED_FUNCTION macro.\n");
        SymCleanup(g_process);
        return 0;
    }

    /* Créer le dossier de sortie */
    create_output_directory();

    /* Ouvrir l'exécutable pour modification */
    printf("→ Opening executable for patching...\n");
    HANDLE hFile = CreateFileA(exe_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("✗ Failed to open executable (Error: %lu)\n", GetLastError());
        SymCleanup(g_process);
        return 1;
    }

    printf("✓ Executable opened\n\n");

    /* Patcher chaque fonction */
    printf("→ Patching functions...\n");
    for (DWORD i = 0; i < protected_function_count; i++) {
        if (patch_function(hFile, &protected_functions[i]) != 0) {
            printf("  ✗ Failed to patch function: %s\n", protected_functions[i].name);
        }
        printf("\n");
    }

    CloseHandle(hFile);

    /* Créer le fichier de métadonnées */
    create_metadata_file();

    /* Cleanup */
    SymCleanup(g_process);

    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("✓ Patching complete!\n");
    printf("  - %u function(s) processed\n", protected_function_count);
    printf("  - Original bytes saved in: %s/\n", OUTPUT_DIR);
    printf("  - Executable patched with NOPs\n");
    printf("═══════════════════════════════════════════════════════════\n");

    return 0;
}

#else

#include <stdio.h>

int main(void) {
    printf("This tool is only available on Windows.\n");
    return 1;
}

#endif
