#include "pe_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Charger un fichier PE depuis le disque */
int pe_load_file(const char* filename, pe_image_t* pe) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("Erreur : impossible d'ouvrir %s\n", filename);
        return -1;
    }

    /* Obtenir la taille du fichier */
    fseek(f, 0, SEEK_END);
    pe->file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Allouer le buffer */
    pe->file_data = (uint8_t*)malloc(pe->file_size);
    if (!pe->file_data) {
        fclose(f);
        return -1;
    }

    /* Lire le fichier */
    if (fread(pe->file_data, 1, pe->file_size, f) != pe->file_size) {
        free(pe->file_data);
        fclose(f);
        return -1;
    }

    fclose(f);

    /* Parser les headers */
    pe->dos_header = (pe_dos_header_t*)pe->file_data;

    if (pe->dos_header->e_magic != PE_MAGIC_MZ) {
        free(pe->file_data);
        return -1;
    }

    uint8_t* nt_header_ptr = pe->file_data + pe->dos_header->e_lfanew;
    uint32_t* signature = (uint32_t*)nt_header_ptr;

    if (*signature != PE_MAGIC_PE) {
        free(pe->file_data);
        return -1;
    }

    /* Déterminer si c'est PE32 ou PE64 */
    uint16_t* magic = (uint16_t*)(nt_header_ptr + 24);  /* Offset du magic dans optional header */

    if (*magic == PE_MAGIC_PE32) {
        pe->is_64bit = 0;
        pe->nt_headers.nt32 = (pe_nt_headers32_t*)nt_header_ptr;
        pe->section_count = pe->nt_headers.nt32->FileHeader.NumberOfSections;
        pe->image_size = pe->nt_headers.nt32->OptionalHeader.SizeOfImage;
        pe->entry_rva = pe->nt_headers.nt32->OptionalHeader.AddressOfEntryPoint;

        /* Pointer vers les sections */
        pe->sections = (pe_section_header_t*)(nt_header_ptr + sizeof(pe_nt_headers32_t));
    } else if (*magic == PE_MAGIC_PE64) {
        pe->is_64bit = 1;
        pe->nt_headers.nt64 = (pe_nt_headers64_t*)nt_header_ptr;
        pe->section_count = pe->nt_headers.nt64->FileHeader.NumberOfSections;
        pe->image_size = pe->nt_headers.nt64->OptionalHeader.SizeOfImage;
        pe->entry_rva = pe->nt_headers.nt64->OptionalHeader.AddressOfEntryPoint;

        /* Pointer vers les sections */
        pe->sections = (pe_section_header_t*)(nt_header_ptr + sizeof(pe_nt_headers64_t));
    } else {
        free(pe->file_data);
        return -1;
    }

    return 0;
}

/* Libérer un PE */
void pe_free(pe_image_t* pe) {
    if (pe->file_data) {
        free(pe->file_data);
        pe->file_data = NULL;
    }
}

/* Valider un PE */
int pe_validate(pe_image_t* pe) {
    if (!pe->file_data) return -1;
    if (pe->dos_header->e_magic != PE_MAGIC_MZ) return -1;

    uint32_t* signature = (uint32_t*)(pe->file_data + pe->dos_header->e_lfanew);
    if (*signature != PE_MAGIC_PE) return -1;

    return 0;
}

/* Convertir RVA en offset fichier */
uint32_t pe_rva_to_offset(pe_image_t* pe, uint32_t rva) {
    for (uint16_t i = 0; i < pe->section_count; i++) {
        pe_section_header_t* section = &pe->sections[i];
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->VirtualSize) {
            return rva - section->VirtualAddress + section->PointerToRawData;
        }
    }
    return 0;
}

/* Trouver la section contenant un RVA */
pe_section_header_t* pe_rva_to_section(pe_image_t* pe, uint32_t rva) {
    for (uint16_t i = 0; i < pe->section_count; i++) {
        pe_section_header_t* section = &pe->sections[i];
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->VirtualSize) {
            return section;
        }
    }
    return NULL;
}

/* Construire le buffer d'imports */
int pe_build_import_buffer(pe_image_t* pe, pe_import_buffer_t* import_buf) {
    /* Initialiser le buffer */
    import_buf->capacity = 65536;  /* 64KB initial */
    import_buf->buffer = (uint8_t*)malloc(import_buf->capacity);
    import_buf->size = 0;

    if (!import_buf->buffer) {
        return -1;
    }

    /* Obtenir la data directory des imports */
    pe_data_directory_t* import_dir;
    if (pe->is_64bit) {
        import_dir = &pe->nt_headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        import_dir = &pe->nt_headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (import_dir->VirtualAddress == 0 || import_dir->Size == 0) {
        /* Pas d'imports */
        return 0;
    }

    /* Obtenir le pointeur vers les import descriptors */
    uint32_t import_offset = pe_rva_to_offset(pe, import_dir->VirtualAddress);
    if (import_offset == 0) {
        free(import_buf->buffer);
        return -1;
    }

    pe_import_descriptor_t* import_desc = (pe_import_descriptor_t*)(pe->file_data + import_offset);

    /* Parcourir les modules */
    while (import_desc->Name != 0) {
        /* Obtenir le nom du module */
        uint32_t name_offset = pe_rva_to_offset(pe, import_desc->Name);
        if (name_offset == 0) {
            import_desc++;
            continue;
        }

        char* module_name = (char*)(pe->file_data + name_offset);
        uint16_t module_name_len = strlen(module_name);

        /* Obtenir les thunks */
        uint32_t thunk_rva = import_desc->OriginalFirstThunk;
        if (thunk_rva == 0) {
            thunk_rva = import_desc->FirstThunk;
        }

        uint32_t thunk_offset = pe_rva_to_offset(pe, thunk_rva);
        uint32_t iat_rva = import_desc->FirstThunk;

        if (pe->is_64bit) {
            pe_thunk_data64_t* thunk = (pe_thunk_data64_t*)(pe->file_data + thunk_offset);

            while (thunk->u1.AddressOfData != 0) {
                /* Vérifier si c'est un ordinal */
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    uint16_t ordinal = (uint16_t)(thunk->u1.Ordinal & 0xFFFF);

                    /* Écrire : module_name_len (2 bytes) */
                    if (import_buf->size + 2 > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, &module_name_len, 2);
                    import_buf->size += 2;

                    /* Écrire : module_name */
                    if (import_buf->size + module_name_len > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, module_name, module_name_len);
                    import_buf->size += module_name_len;

                    /* Écrire : function_name_len = 0 pour ordinal, puis ordinal (2 bytes) */
                    uint16_t fn_len = 0;
                    if (import_buf->size + 4 > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, &fn_len, 2);
                    import_buf->size += 2;
                    memcpy(import_buf->buffer + import_buf->size, &ordinal, 2);
                    import_buf->size += 2;

                    /* Écrire : IAT RVA (4 bytes) */
                    if (import_buf->size + 4 > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, &iat_rva, 4);
                    import_buf->size += 4;
                } else {
                    /* Import par nom */
                    uint32_t name_table_offset = pe_rva_to_offset(pe, (uint32_t)thunk->u1.AddressOfData);
                    if (name_table_offset != 0) {
                        pe_import_by_name_t* import_by_name = (pe_import_by_name_t*)(pe->file_data + name_table_offset);
                        char* function_name = import_by_name->Name;
                        uint16_t function_name_len = strlen(function_name);

                        /* Écrire : module_name_len (2 bytes) */
                        if (import_buf->size + 2 > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, &module_name_len, 2);
                        import_buf->size += 2;

                        /* Écrire : module_name */
                        if (import_buf->size + module_name_len > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, module_name, module_name_len);
                        import_buf->size += module_name_len;

                        /* Écrire : function_name_len (2 bytes) */
                        if (import_buf->size + 2 > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, &function_name_len, 2);
                        import_buf->size += 2;

                        /* Écrire : function_name */
                        if (import_buf->size + function_name_len > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, function_name, function_name_len);
                        import_buf->size += function_name_len;

                        /* Écrire : IAT RVA (4 bytes) */
                        if (import_buf->size + 4 > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, &iat_rva, 4);
                        import_buf->size += 4;
                    }
                }

                thunk++;
                iat_rva += 8;  /* 64-bit pointer */
            }
        } else {
            /* PE32 */
            pe_thunk_data32_t* thunk = (pe_thunk_data32_t*)(pe->file_data + thunk_offset);

            while (thunk->u1.AddressOfData != 0) {
                /* Vérifier si c'est un ordinal */
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    uint16_t ordinal = (uint16_t)(thunk->u1.Ordinal & 0xFFFF);

                    /* Écrire : module_name_len (2 bytes) */
                    if (import_buf->size + 2 > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, &module_name_len, 2);
                    import_buf->size += 2;

                    /* Écrire : module_name */
                    if (import_buf->size + module_name_len > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, module_name, module_name_len);
                    import_buf->size += module_name_len;

                    /* Écrire : function_name_len = 0 pour ordinal, puis ordinal (2 bytes) */
                    uint16_t fn_len = 0;
                    if (import_buf->size + 4 > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, &fn_len, 2);
                    import_buf->size += 2;
                    memcpy(import_buf->buffer + import_buf->size, &ordinal, 2);
                    import_buf->size += 2;

                    /* Écrire : IAT RVA (4 bytes) */
                    if (import_buf->size + 4 > import_buf->capacity) {
                        import_buf->capacity *= 2;
                        import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                    }
                    memcpy(import_buf->buffer + import_buf->size, &iat_rva, 4);
                    import_buf->size += 4;
                } else {
                    /* Import par nom */
                    uint32_t name_table_offset = pe_rva_to_offset(pe, thunk->u1.AddressOfData);
                    if (name_table_offset != 0) {
                        pe_import_by_name_t* import_by_name = (pe_import_by_name_t*)(pe->file_data + name_table_offset);
                        char* function_name = import_by_name->Name;
                        uint16_t function_name_len = strlen(function_name);

                        /* Écrire : module_name_len (2 bytes) */
                        if (import_buf->size + 2 > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, &module_name_len, 2);
                        import_buf->size += 2;

                        /* Écrire : module_name */
                        if (import_buf->size + module_name_len > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, module_name, module_name_len);
                        import_buf->size += module_name_len;

                        /* Écrire : function_name_len (2 bytes) */
                        if (import_buf->size + 2 > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, &function_name_len, 2);
                        import_buf->size += 2;

                        /* Écrire : function_name */
                        if (import_buf->size + function_name_len > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, function_name, function_name_len);
                        import_buf->size += function_name_len;

                        /* Écrire : IAT RVA (4 bytes) */
                        if (import_buf->size + 4 > import_buf->capacity) {
                            import_buf->capacity *= 2;
                            import_buf->buffer = (uint8_t*)realloc(import_buf->buffer, import_buf->capacity);
                        }
                        memcpy(import_buf->buffer + import_buf->size, &iat_rva, 4);
                        import_buf->size += 4;
                    }
                }

                thunk++;
                iat_rva += 4;  /* 32-bit pointer */
            }
        }

        import_desc++;
    }

    return 0;
}

/* Libérer le buffer d'imports */
void pe_free_import_buffer(pe_import_buffer_t* import_buf) {
    if (import_buf->buffer) {
        free(import_buf->buffer);
        import_buf->buffer = NULL;
    }
    import_buf->size = 0;
    import_buf->capacity = 0;
}

/* Mapper les sections en mémoire */
int pe_map_sections(pe_image_t* pe, uint8_t* dest_buffer) {
    /* Initialiser le buffer avec des zéros */
    memset(dest_buffer, 0, pe->image_size);

    /* Copier les headers */
    uint32_t headers_size;
    if (pe->is_64bit) {
        headers_size = pe->nt_headers.nt64->OptionalHeader.SizeOfHeaders;
    } else {
        headers_size = pe->nt_headers.nt32->OptionalHeader.SizeOfHeaders;
    }
    memcpy(dest_buffer, pe->file_data, headers_size);

    /* Copier chaque section */
    for (uint16_t i = 0; i < pe->section_count; i++) {
        pe_section_header_t* section = &pe->sections[i];

        if (section->SizeOfRawData == 0) {
            continue;
        }

        uint32_t dest_offset = section->VirtualAddress;
        uint32_t src_offset = section->PointerToRawData;
        uint32_t size = section->SizeOfRawData;

        memcpy(dest_buffer + dest_offset, pe->file_data + src_offset, size);
    }

    return 0;
}

/* Appliquer les relocations */
int pe_apply_relocations(pe_image_t* pe, uint8_t* image_buffer, uint64_t new_base) {
    /* Obtenir l'ancienne base */
    uint64_t old_base;
    if (pe->is_64bit) {
        old_base = pe->nt_headers.nt64->OptionalHeader.ImageBase;
    } else {
        old_base = pe->nt_headers.nt32->OptionalHeader.ImageBase;
    }

    /* Calculer le delta */
    int64_t delta = (int64_t)new_base - (int64_t)old_base;

    if (delta == 0) {
        /* Pas besoin de relocations */
        return 0;
    }

    /* Obtenir la data directory des relocations */
    pe_data_directory_t* reloc_dir;
    if (pe->is_64bit) {
        reloc_dir = &pe->nt_headers.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
        reloc_dir = &pe->nt_headers.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    if (reloc_dir->VirtualAddress == 0 || reloc_dir->Size == 0) {
        /* Pas de relocations */
        return 0;
    }

    uint32_t reloc_offset = reloc_dir->VirtualAddress;
    uint32_t reloc_end = reloc_offset + reloc_dir->Size;

    while (reloc_offset < reloc_end) {
        pe_base_relocation_t* reloc_block = (pe_base_relocation_t*)(image_buffer + reloc_offset);

        if (reloc_block->SizeOfBlock == 0) {
            break;
        }

        uint32_t entry_count = (reloc_block->SizeOfBlock - sizeof(pe_base_relocation_t)) / 2;
        uint16_t* entries = (uint16_t*)((uint8_t*)reloc_block + sizeof(pe_base_relocation_t));

        for (uint32_t i = 0; i < entry_count; i++) {
            uint16_t entry = entries[i];
            uint16_t type = entry >> 12;
            uint16_t offset = entry & 0xFFF;

            uint32_t rva = reloc_block->VirtualAddress + offset;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                /* Pas de relocation */
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                /* 32-bit */
                uint32_t* patch_addr = (uint32_t*)(image_buffer + rva);
                *patch_addr = (uint32_t)((int64_t)*patch_addr + delta);
            } else if (type == IMAGE_REL_BASED_DIR64) {
                /* 64-bit */
                uint64_t* patch_addr = (uint64_t*)(image_buffer + rva);
                *patch_addr = (uint64_t)((int64_t)*patch_addr + delta);
            }
        }

        reloc_offset += reloc_block->SizeOfBlock;
    }

    return 0;
}
