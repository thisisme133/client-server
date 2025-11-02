#pragma once

#include <cstdint>
#include <span>
#include <expected>
#include <string_view>

namespace compression {

// Simple RLE compression (fast, low overhead)
class RLE {
public:
    [[nodiscard]] static std::expected<size_t, std::string_view>
    compress(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
        if (output.size() < input.size() * 2) {
            return std::unexpected("Output buffer too small");
        }

        size_t out_idx = 0;
        size_t in_idx = 0;

        while (in_idx < input.size()) {
            uint8_t current = input[in_idx];
            uint8_t count = 1;

            // Count consecutive identical bytes (max 255)
            while (in_idx + count < input.size() &&
                   input[in_idx + count] == current &&
                   count < 255) {
                ++count;
            }

            // Write count + byte
            if (out_idx + 2 > output.size()) {
                return std::unexpected("Output overflow");
            }

            output[out_idx++] = count;
            output[out_idx++] = current;
            in_idx += count;
        }

        return out_idx;
    }

    [[nodiscard]] static std::expected<size_t, std::string_view>
    decompress(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
        if (input.size() % 2 != 0) {
            return std::unexpected("Invalid compressed data");
        }

        size_t out_idx = 0;

        for (size_t in_idx = 0; in_idx < input.size(); in_idx += 2) {
            uint8_t count = input[in_idx];
            uint8_t value = input[in_idx + 1];

            if (out_idx + count > output.size()) {
                return std::unexpected("Output overflow");
            }

            for (uint8_t i = 0; i < count; ++i) {
                output[out_idx++] = value;
            }
        }

        return out_idx;
    }

    [[nodiscard]] static constexpr bool should_compress(std::span<const uint8_t> data) noexcept {
        // Only compress if data is large enough and has repetition potential
        if (data.size() < 256) return false;

        // Quick heuristic: check if there's repetition in first 256 bytes
        size_t check_size = std::min(data.size(), size_t{256});
        uint32_t repetition_count = 0;

        for (size_t i = 1; i < check_size; ++i) {
            if (data[i] == data[i - 1]) {
                ++repetition_count;
            }
        }

        // If more than 25% repetition, worth compressing
        return repetition_count > (check_size / 4);
    }
};

} // namespace compression
