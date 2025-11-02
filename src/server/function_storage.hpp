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
#include <optional>

namespace fs = std::filesystem;

namespace server {

// Simple checksum for integrity (matches client-side implementation)
inline uint32_t compute_checksum(std::span<const uint8_t> data) noexcept {
    uint32_t checksum = 0x5A5A5A5A;
    for (size_t i = 0; i < data.size(); ++i) {
        checksum ^= data[i];
        checksum = (checksum << 7) | (checksum >> 25);
        checksum += i * 0x01000193;
    }
    return checksum;
}

// Function storage class - loads from patcher output
class FunctionStorage {
    struct FunctionInfo {
        uint32_t marker_hash;
        std::string name;
        std::string filename;
        std::vector<uint8_t> bytecode;
        size_t size;
        uint32_t checksum;  // Integrity verification
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

            // Compute checksum for integrity verification
            info.checksum = compute_checksum(info.bytecode);

            std::cout << "Loaded: " << info.name << " (" << info.size << " bytes, checksum: 0x"
                     << std::hex << info.checksum << std::dec << ")\n";
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

    // Get complete function info for secure transmission
    struct FunctionData {
        std::string_view name;
        std::span<const uint8_t> bytecode;
        uint32_t checksum;
    };

    std::optional<FunctionData> get_function_info(uint32_t marker_hash) const {
        auto it = functions_.find(marker_hash);
        if (it != functions_.end()) {
            return FunctionData{
                it->second.name,
                std::span{it->second.bytecode},
                it->second.checksum
            };
        }
        return std::nullopt;
    }

    bool has_function(uint32_t marker_hash) const {
        return functions_.contains(marker_hash);
    }

    static FunctionStorage& instance() {
        static FunctionStorage storage;
        return storage;
    }

private:
    // Helper: extract string value from JSON field "key": "value"
    std::string extract_string_value(const std::string& line, const std::string& key) {
        auto key_pos = line.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return {};

        auto colon_pos = line.find(":", key_pos);
        if (colon_pos == std::string::npos) return {};

        auto start = line.find("\"", colon_pos);
        if (start == std::string::npos) return {};
        start++;

        auto end = line.find("\"", start);
        if (end == std::string::npos) return {};

        return line.substr(start, end - start);
    }

    // Helper: extract numeric value from JSON field "key": value
    std::string extract_number_value(const std::string& line, const std::string& key) {
        auto key_pos = line.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return {};

        auto colon_pos = line.find(":", key_pos);
        if (colon_pos == std::string::npos) return {};

        auto start = colon_pos + 1;
        // Skip whitespace
        while (start < line.size() && std::isspace(line[start])) start++;

        auto end = start;
        while (end < line.size() && (std::isdigit(line[end]) || line[end] == '-')) end++;

        if (start >= line.size()) return {};
        return line.substr(start, end - start);
    }

    // Robust JSON parser for manifest format
    // Tolerates extra whitespace, different field orders, and formatting variations
    bool parse_manifest(const fs::path& manifest_path) {
        std::ifstream file(manifest_path);
        if (!file) {
            std::cerr << "Cannot open manifest file\n";
            return false;
        }

        // Read entire file into a single string
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());

        // Parse line by line, accumulating fields
        std::istringstream stream(content);
        std::string line;
        FunctionInfo current_func;
        bool in_function_object = false;
        int fields_found = 0;

        while (std::getline(stream, line)) {
            // Remove leading/trailing whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            if (!line.empty()) {
                line.erase(line.find_last_not_of(" \t\r\n,") + 1);
            }

            if (line.empty()) continue;

            // Detect start of function object
            if (line.find("{") != std::string::npos && in_function_object == false) {
                in_function_object = true;
                current_func = FunctionInfo{};
                fields_found = 0;
                continue;
            }

            // Detect end of function object
            if (line.find("}") != std::string::npos && in_function_object) {
                // Validate we have all required fields
                if (fields_found >= 4 && !current_func.name.empty() &&
                    current_func.marker_hash != 0 && !current_func.filename.empty() &&
                    current_func.size > 0) {

                    // Detect hash collision
                    if (functions_.contains(current_func.marker_hash)) {
                        std::cerr << "Warning: Hash collision for " << current_func.name
                                 << " (hash: 0x" << std::hex << current_func.marker_hash << std::dec << ")\n";
                    }

                    functions_[current_func.marker_hash] = current_func;
                } else {
                    std::cerr << "Warning: Incomplete function entry skipped (fields: "
                             << fields_found << ")\n";
                }

                in_function_object = false;
                continue;
            }

            if (!in_function_object) continue;

            // Extract fields (order-independent)
            if (auto name = extract_string_value(line, "name"); !name.empty()) {
                current_func.name = name;
                fields_found++;
            }
            else if (auto hash_str = extract_number_value(line, "hash"); !hash_str.empty()) {
                // Parse hash - simple validation
                bool valid = true;
                for (char c : hash_str) {
                    if (!std::isdigit(c)) { valid = false; break; }
                }
                if (valid) {
                    current_func.marker_hash = std::stoul(hash_str);
                    fields_found++;
                } else {
                    std::cerr << "Warning: Invalid hash value: " << hash_str << "\n";
                }
            }
            else if (auto filename = extract_string_value(line, "file"); !filename.empty()) {
                current_func.filename = filename;
                fields_found++;
            }
            else if (auto size_str = extract_number_value(line, "size"); !size_str.empty()) {
                // Parse size - simple validation
                bool valid = true;
                for (char c : size_str) {
                    if (!std::isdigit(c)) { valid = false; break; }
                }
                if (valid) {
                    current_func.size = std::stoull(size_str);
                    fields_found++;
                } else {
                    std::cerr << "Warning: Invalid size value: " << size_str << "\n";
                }
            }
        }

        if (functions_.empty()) {
            std::cerr << "Error: No valid functions found in manifest\n";
            return false;
        }

        return true;
    }
};

} // namespace server
