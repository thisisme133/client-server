#pragma once

#define PROTECTED_FUNCTION_SERVER
#include "protected_function.hpp"
#include <unordered_map>
#include <vector>
#include <span>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace server {

// Function storage class - loads from patcher output
class FunctionStorage {
    struct FunctionInfo {
        uint32_t marker_hash;
        std::string name;
        std::string filename;
        std::vector<uint8_t> bytecode;
        size_t size;
    };

    std::unordered_map<uint32_t, FunctionInfo> functions_;
    fs::path functions_dir_;

public:
    FunctionStorage() = default;

    // Load functions from directory created by function_patcher
    bool load_from_directory(const fs::path& functions_dir) {
        functions_dir_ = functions_dir;

        if (!fs::exists(functions_dir)) {
            std::cerr << "Functions directory not found: " << functions_dir << "\n";
            return false;
        }

        // Parse manifest.json
        fs::path manifest_path = functions_dir / "manifest.json";
        if (!fs::exists(manifest_path)) {
            std::cerr << "Manifest not found: " << manifest_path << "\n";
            return false;
        }

        if (!parse_manifest(manifest_path)) {
            std::cerr << "Failed to parse manifest\n";
            return false;
        }

        // Load bytecode for each function
        for (auto& [hash, info] : functions_) {
            fs::path bytecode_path = functions_dir / info.filename;
            if (!fs::exists(bytecode_path)) {
                std::cerr << "Bytecode file not found: " << bytecode_path << "\n";
                continue;
            }

            std::ifstream file(bytecode_path, std::ios::binary);
            if (!file) {
                std::cerr << "Failed to open: " << bytecode_path << "\n";
                continue;
            }

            info.bytecode.resize(info.size);
            file.read(reinterpret_cast<char*>(info.bytecode.data()), info.size);

            std::cout << "Loaded: " << info.name << " (" << info.size << " bytes)\n";
        }

        std::cout << "Loaded " << functions_.size() << " protected functions\n";
        return !functions_.empty();
    }

    std::span<const uint8_t> get_function_code(uint32_t marker_hash) const {
        auto it = functions_.find(marker_hash);
        if (it != functions_.end()) {
            return std::span{it->second.bytecode};
        }
        return {};
    }

    bool has_function(uint32_t marker_hash) const {
        return functions_.contains(marker_hash);
    }

    static FunctionStorage& instance() {
        static FunctionStorage storage;
        return storage;
    }

private:
    // Simple JSON parser for our manifest format
    bool parse_manifest(const fs::path& manifest_path) {
        std::ifstream file(manifest_path);
        if (!file) return false;

        std::string line;
        FunctionInfo current_func;
        bool in_function = false;

        while (std::getline(file, line)) {
            // Remove whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty() || line[0] == '{' || line[0] == '}') continue;

            // Start of function object
            if (line == "\"functions\": [") {
                continue;
            }

            // Parse function fields
            if (line.find("\"name\":") != std::string::npos) {
                in_function = true;
                size_t start = line.find("\"", 8) + 1;
                size_t end = line.find("\"", start);
                current_func.name = line.substr(start, end - start);
            }
            else if (line.find("\"hash\":") != std::string::npos) {
                size_t start = line.find(":") + 1;
                size_t end = line.find_first_of(",}", start);
                std::string hash_str = line.substr(start, end - start);
                current_func.marker_hash = std::stoul(hash_str);
            }
            else if (line.find("\"file\":") != std::string::npos) {
                size_t start = line.find("\"", 8) + 1;
                size_t end = line.find("\"", start);
                current_func.filename = line.substr(start, end - start);
            }
            else if (line.find("\"size\":") != std::string::npos) {
                size_t start = line.find(":") + 1;
                size_t end = line.find_first_of(",}", start);
                std::string size_str = line.substr(start, end - start);
                current_func.size = std::stoull(size_str);

                // End of function object
                functions_[current_func.marker_hash] = current_func;
                current_func = FunctionInfo{};
                in_function = false;
            }
        }

        return !functions_.empty();
    }
};

} // namespace server
