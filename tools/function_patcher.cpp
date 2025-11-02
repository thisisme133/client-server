#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <string>
#include <cstdint>
#include <format>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

namespace fs = std::filesystem;

// FNV1a hash (same as in protected_function.hpp)
constexpr uint32_t fnv1a_hash(std::string_view str) noexcept {
    uint32_t hash = 2166136261u;
    for (char c : str) {
        hash ^= static_cast<uint32_t>(c);
        hash *= 16777619u;
    }
    return hash;
}

struct FunctionInfo {
    std::string name;
    uint32_t hash;
    uint64_t rva;           // Relative Virtual Address
    uint64_t size;
    std::vector<uint8_t> original_bytes;
};

class FunctionPatcher {
    std::vector<FunctionInfo> functions_;
    fs::path exe_path_;
    fs::path pdb_path_;
    fs::path output_dir_;

#ifdef _WIN32
    HANDLE process_handle_ = nullptr;
#endif

public:
    FunctionPatcher(fs::path exe, fs::path pdb, fs::path output)
        : exe_path_(std::move(exe))
        , pdb_path_(std::move(pdb))
        , output_dir_(std::move(output)) {

        fs::create_directories(output_dir_);
    }

    ~FunctionPatcher() {
#ifdef _WIN32
        if (process_handle_) {
            SymCleanup(process_handle_);
        }
#endif
    }

    bool parse_pdb() {
#ifdef _WIN32
        process_handle_ = GetCurrentProcess();

        if (!SymInitialize(process_handle_, nullptr, FALSE)) {
            std::cerr << "SymInitialize failed: " << GetLastError() << "\n";
            return false;
        }

        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

        DWORD64 base_address = SymLoadModuleEx(
            process_handle_,
            nullptr,
            exe_path_.string().c_str(),
            nullptr,
            0x400000, // Base address
            0,
            nullptr,
            0
        );

        if (base_address == 0) {
            std::cerr << "SymLoadModuleEx failed: " << GetLastError() << "\n";
            return false;
        }

        std::cout << "PDB loaded at base: 0x" << std::hex << base_address << std::dec << "\n";

        // Enumerate all symbols
        if (!SymEnumSymbols(
            process_handle_,
            base_address,
            nullptr,
            [](PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL {
                auto* patcher = static_cast<FunctionPatcher*>(UserContext);
                return patcher->process_symbol(pSymInfo, SymbolSize);
            },
            this
        )) {
            std::cerr << "SymEnumSymbols failed: " << GetLastError() << "\n";
            return false;
        }

        std::cout << "Found " << functions_.size() << " protected functions\n";
        return !functions_.empty();
#else
        std::cerr << "PDB parsing only supported on Windows\n";
        return false;
#endif
    }

#ifdef _WIN32
    BOOL process_symbol(PSYMBOL_INFO sym_info, ULONG sym_size) {
        std::string name(sym_info->Name);

        // Look for functions with our naming convention
        // Functions defined with MARKER_DEF will have specific patterns
        // For simplicity, we look for known function names
        static const std::vector<std::string> protected_functions = {
            "SetProcessAsCritical",
            "check_debugger_present",
            "check_vm_present",
            "find_process_by_name",
            "validate_pe",
            "inject_pe"
        };

        for (const auto& func_name : protected_functions) {
            if (name.find(func_name) != std::string::npos) {
                FunctionInfo info;
                info.name = func_name;
                info.hash = fnv1a_hash(func_name);
                info.rva = sym_info->Address - sym_info->ModBase;
                info.size = sym_size > 0 ? sym_size : 512; // Default size if not available

                std::cout << std::format("Found: {} at RVA 0x{:X} (size: {})\n",
                    info.name, info.rva, info.size);

                functions_.push_back(info);
                break;
            }
        }

        return TRUE;
    }
#endif

    bool extract_function_bytes() {
        std::ifstream exe(exe_path_, std::ios::binary);
        if (!exe) {
            std::cerr << "Failed to open exe: " << exe_path_ << "\n";
            return false;
        }

        // Read entire exe into memory
        std::vector<uint8_t> exe_data(
            (std::istreambuf_iterator<char>(exe)),
            std::istreambuf_iterator<char>()
        );

        // Parse PE headers to convert RVA to file offset
        if (exe_data.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cerr << "Invalid exe file\n";
            return false;
        }

        auto* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(exe_data.data());
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid DOS signature\n";
            return false;
        }

        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
            exe_data.data() + dos_header->e_lfanew
        );
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid PE signature\n";
            return false;
        }

        // For each function, extract bytes
        for (auto& func : functions_) {
            uint64_t file_offset = rva_to_file_offset(func.rva, nt_headers);
            if (file_offset == 0 || file_offset + func.size > exe_data.size()) {
                std::cerr << "Invalid file offset for " << func.name << "\n";
                continue;
            }

            func.original_bytes.resize(func.size);
            std::memcpy(
                func.original_bytes.data(),
                exe_data.data() + file_offset,
                func.size
            );

            std::cout << std::format("Extracted {} bytes from {}\n",
                func.size, func.name);
        }

        return true;
    }

    uint64_t rva_to_file_offset(uint64_t rva, IMAGE_NT_HEADERS* nt_headers) {
        auto* section = IMAGE_FIRST_SECTION(nt_headers);
        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
            if (rva >= section->VirtualAddress &&
                rva < section->VirtualAddress + section->Misc.VirtualSize) {
                return rva - section->VirtualAddress + section->PointerToRawData;
            }
        }
        return 0;
    }

    bool save_original_functions() {
        for (const auto& func : functions_) {
            fs::path output_file = output_dir_ / std::format("{:08X}.bin", func.hash);

            std::ofstream out(output_file, std::ios::binary);
            if (!out) {
                std::cerr << "Failed to write: " << output_file << "\n";
                return false;
            }

            out.write(
                reinterpret_cast<const char*>(func.original_bytes.data()),
                func.original_bytes.size()
            );

            std::cout << std::format("Saved: {} -> {}\n", func.name, output_file.string());
        }

        return true;
    }

    bool create_manifest() {
        fs::path manifest_path = output_dir_ / "manifest.json";
        std::ofstream manifest(manifest_path);
        if (!manifest) {
            std::cerr << "Failed to create manifest\n";
            return false;
        }

        manifest << "{\n";
        manifest << "  \"version\": 1,\n";
        manifest << "  \"functions\": [\n";

        for (size_t i = 0; i < functions_.size(); ++i) {
            const auto& func = functions_[i];
            manifest << std::format("    {{\n");
            manifest << std::format("      \"name\": \"{}\",\n", func.name);
            manifest << std::format("      \"hash\": {:u},\n", func.hash);
            manifest << std::format("      \"file\": \"{:08X}.bin\",\n", func.hash);
            manifest << std::format("      \"size\": {}\n", func.size);
            manifest << std::format("    }}{}\n", (i < functions_.size() - 1) ? "," : "");
        }

        manifest << "  ]\n";
        manifest << "}\n";

        std::cout << "Created manifest: " << manifest_path << "\n";
        return true;
    }

    bool patch_exe_with_nops() {
        fs::path patched_path = exe_path_;
        patched_path.replace_filename(exe_path_.stem().string() + "_patched.exe");

        // Copy original to patched
        fs::copy_file(exe_path_, patched_path, fs::copy_options::overwrite_existing);

        std::fstream patched(patched_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!patched) {
            std::cerr << "Failed to open patched exe\n";
            return false;
        }

        // Read PE headers
        IMAGE_DOS_HEADER dos_header;
        patched.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));

        patched.seekg(dos_header.e_lfanew);
        IMAGE_NT_HEADERS nt_headers;
        patched.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));

        // NOP out each function
        for (const auto& func : functions_) {
            uint64_t file_offset = rva_to_file_offset(func.rva, &nt_headers);
            if (file_offset == 0) continue;

            patched.seekp(file_offset);
            std::vector<uint8_t> nops(func.size, 0x90); // 0x90 = NOP
            patched.write(reinterpret_cast<const char*>(nops.data()), nops.size());

            std::cout << std::format("NOPed: {} ({} bytes)\n", func.name, func.size);
        }

        std::cout << "Created patched exe: " << patched_path << "\n";
        return true;
    }

    bool run() {
        std::cout << "=== Function Patcher Tool ===\n";
        std::cout << "EXE: " << exe_path_ << "\n";
        std::cout << "PDB: " << pdb_path_ << "\n";
        std::cout << "Output: " << output_dir_ << "\n\n";

        if (!parse_pdb()) {
            std::cerr << "Failed to parse PDB\n";
            return false;
        }

        if (!extract_function_bytes()) {
            std::cerr << "Failed to extract function bytes\n";
            return false;
        }

        if (!save_original_functions()) {
            std::cerr << "Failed to save functions\n";
            return false;
        }

        if (!create_manifest()) {
            std::cerr << "Failed to create manifest\n";
            return false;
        }

        if (!patch_exe_with_nops()) {
            std::cerr << "Failed to patch exe\n";
            return false;
        }

        std::cout << "\n=== Success! ===\n";
        std::cout << functions_.size() << " functions processed\n";
        return true;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: function_patcher <exe> <pdb> [output_dir]\n";
        std::cerr << "Example: function_patcher client.exe client.pdb functions\n";
        return 1;
    }

    fs::path exe_path = argv[1];
    fs::path pdb_path = argv[2];
    fs::path output_dir = argc > 3 ? argv[3] : "functions";

    if (!fs::exists(exe_path)) {
        std::cerr << "EXE not found: " << exe_path << "\n";
        return 1;
    }

    if (!fs::exists(pdb_path)) {
        std::cerr << "PDB not found: " << pdb_path << "\n";
        return 1;
    }

    FunctionPatcher patcher(exe_path, pdb_path, output_dir);
    return patcher.run() ? 0 : 1;
}
