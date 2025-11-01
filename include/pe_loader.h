#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>

/* DOS Header */
typedef struct __attribute__((packed)) {
    uint16_t e_magic;      /* Magic number "MZ" */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;     /* Offset vers NT headers */
} pe_dos_header_t;

/* File Header */
typedef struct __attribute__((packed)) {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_file_header_t;

/* Data Directory */
typedef struct __attribute__((packed)) {
    uint32_t VirtualAddress;
    uint32_t Size;
} pe_data_directory_t;

/* Optional Header 32 */
typedef struct __attribute__((packed)) {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[16];
} pe_optional_header32_t;

/* Optional Header 64 */
typedef struct __attribute__((packed)) {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[16];
} pe_optional_header64_t;

/* NT Headers 32 */
typedef struct __attribute__((packed)) {
    uint32_t Signature;
    pe_file_header_t FileHeader;
    pe_optional_header32_t OptionalHeader;
} pe_nt_headers32_t;

/* NT Headers 64 */
typedef struct __attribute__((packed)) {
    uint32_t Signature;
    pe_file_header_t FileHeader;
    pe_optional_header64_t OptionalHeader;
} pe_nt_headers64_t;

/* Section Header */
typedef struct __attribute__((packed)) {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_header_t;

/* Import Descriptor */
typedef struct __attribute__((packed)) {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} pe_import_descriptor_t;

/* Base Relocation Block */
typedef struct __attribute__((packed)) {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
} pe_base_relocation_t;

/* Import Thunk 32 */
typedef struct __attribute__((packed)) {
    union {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;
    } u1;
} pe_thunk_data32_t;

/* Import Thunk 64 */
typedef struct __attribute__((packed)) {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;
    } u1;
} pe_thunk_data64_t;

/* Import By Name */
typedef struct __attribute__((packed)) {
    uint16_t Hint;
    char Name[1];
} pe_import_by_name_t;

/* Structure pour stocker les infos d'un PE chargé */
typedef struct {
    uint8_t* file_data;        /* Données du fichier PE */
    uint32_t file_size;        /* Taille du fichier */
    uint8_t is_64bit;          /* 1 si PE64, 0 si PE32 */

    pe_dos_header_t* dos_header;
    union {
        pe_nt_headers32_t* nt32;
        pe_nt_headers64_t* nt64;
    } nt_headers;

    pe_section_header_t* sections;
    uint16_t section_count;

    uint32_t image_size;
    uint32_t entry_rva;
} pe_image_t;

/* Structure pour un import */
typedef struct {
    char module_name[256];
    char function_name[256];
    uint32_t iat_rva;          /* RVA de l'entrée dans l'IAT */
    uint8_t is_ordinal;
    uint16_t ordinal;
} pe_import_entry_t;

/* Structure pour le buffer d'imports */
typedef struct {
    uint8_t* buffer;
    uint32_t size;
    uint32_t capacity;
} pe_import_buffer_t;

/* Constantes */
#define PE_MAGIC_MZ 0x5A4D
#define PE_MAGIC_PE 0x00004550
#define PE_MAGIC_PE32 0x010B
#define PE_MAGIC_PE64 0x020B

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_DIR64 10

#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

/* Fonctions de parsing PE */
int pe_load_file(const char* filename, pe_image_t* pe);
void pe_free(pe_image_t* pe);
int pe_validate(pe_image_t* pe);

/* Fonctions pour construire le buffer d'imports */
int pe_build_import_buffer(pe_image_t* pe, pe_import_buffer_t* import_buf);
void pe_free_import_buffer(pe_import_buffer_t* import_buf);

/* Fonctions pour mapper l'image en mémoire */
int pe_map_sections(pe_image_t* pe, uint8_t* dest_buffer);

/* Fonctions pour appliquer les relocations */
int pe_apply_relocations(pe_image_t* pe, uint8_t* image_buffer, uint64_t new_base);

/* Utilitaires */
uint32_t pe_rva_to_offset(pe_image_t* pe, uint32_t rva);
pe_section_header_t* pe_rva_to_section(pe_image_t* pe, uint32_t rva);

#endif
