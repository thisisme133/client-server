#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <concepts>

namespace crypto {

// Concepts
template<typename T>
concept KeyType = requires(T key) {
    { key.data() } -> std::convertible_to<const uint8_t*>;
    { key.size() } -> std::convertible_to<size_t>;
};

// Compile-time XOR cipher (fast, inline)
template<KeyType K>
constexpr void xor_cipher(std::span<uint8_t> data, const K& key) noexcept {
    const auto key_span = std::span{key.data(), key.size()};

    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key_span[i % key_span.size()];
    }
}

// Inline encryption/decryption (same operation for XOR)
template<KeyType K>
inline void encrypt(const K& key, std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
    const auto key_span = std::span{key.data(), key.size()};
    const size_t size = std::min(input.size(), output.size());

    for (size_t i = 0; i < size; ++i) {
        output[i] = input[i] ^ key_span[i % key_span.size()];
    }
}

template<KeyType K>
inline void decrypt(const K& key, std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
    encrypt(key, input, output);  // XOR is symmetric
}

// Challenge solving (constexpr for compile-time evaluation if possible)
[[nodiscard]] constexpr uint32_t solve_challenge(uint32_t challenge) noexcept {
    // Simple hash-based challenge (example: use a more complex one in production)
    uint32_t result = challenge;
    result ^= (result << 13);
    result ^= (result >> 17);
    result ^= (result << 5);
    return result * 0x9E3779B9;
}

// Fast CRC32 (optimized with lookup table)
class CRC32 {
    static constexpr auto generate_table() noexcept {
        std::array<uint32_t, 256> table{};

        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i;
            for (uint32_t j = 0; j < 8; ++j) {
                crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
            }
            table[i] = crc;
        }

        return table;
    }

    static constexpr auto table = generate_table();

public:
    [[nodiscard]] static constexpr uint32_t compute(std::span<const uint8_t> data) noexcept {
        uint32_t crc = 0xFFFFFFFF;

        for (uint8_t byte : data) {
            crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
        }

        return ~crc;
    }

    [[nodiscard]] static constexpr uint32_t compute(const void* data, size_t size) noexcept {
        return compute(std::span{static_cast<const uint8_t*>(data), size});
    }
};

} // namespace crypto
