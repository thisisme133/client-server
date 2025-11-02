#pragma once

#include <cstdint>
#include <ctime>
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

// CRC32 lookup table (compile-time generated)
inline constexpr auto crc32_table = []() constexpr {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320 : 0);
        }
        table[i] = crc;
    }
    return table;
}();

// Fast CRC32 (optimized with lookup table)
class CRC32 {
public:
    [[nodiscard]] static constexpr uint32_t compute(std::span<const uint8_t> data) noexcept {
        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : data) {
            crc = crc32_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
        }
        return ~crc;
    }

    [[nodiscard]] static constexpr uint32_t compute(const void* data, size_t size) noexcept {
        return compute(std::span{static_cast<const uint8_t*>(data), size});
    }
};

// SHA256-like hashing function (simplified for proof-of-work)
[[nodiscard]] inline uint64_t hash64(uint64_t x) noexcept {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

// Complex proof-of-work challenge solver
// Combines multiple hash iterations with session key and timestamp
// This makes it computationally expensive and tied to the specific session
struct HeartbeatChallenge {
    uint64_t nonce;
    uint64_t timestamp;
    uint32_t difficulty;  // Number of hash iterations required
    uint32_t session_id;
};

struct HeartbeatSolution {
    uint64_t solution;
    uint64_t client_timestamp;
    uint32_t client_state_hash;  // Hash of client anti-debug/VM checks
    uint32_t reserved;
};

// Solve heartbeat challenge with proof-of-work
// This function is designed to be hard to emulate because:
// 1. Requires multiple iterations (difficulty parameter)
// 2. Uses session-specific data (session_key)
// 3. Incorporates client state (anti-debug checks)
// 4. Time-sensitive (timestamp validation)
template<KeyType K>
[[nodiscard]] inline HeartbeatSolution solve_heartbeat_challenge(
    const HeartbeatChallenge& challenge,
    const K& session_key,
    uint32_t client_state_hash) noexcept
{
    HeartbeatSolution solution{};

    // Start with challenge nonce
    uint64_t hash = challenge.nonce;

    // Mix in session key bytes
    for (size_t i = 0; i < session_key.size(); ++i) {
        hash = hash64(hash ^ (static_cast<uint64_t>(session_key.data()[i]) << (i % 8)));
    }

    // Mix in timestamp
    hash = hash64(hash ^ challenge.timestamp);

    // Mix in session ID
    hash = hash64(hash ^ challenge.session_id);

    // Proof-of-work: perform difficulty iterations
    for (uint32_t i = 0; i < challenge.difficulty; ++i) {
        hash = hash64(hash ^ i);
    }

    // Mix in client state (anti-debug, anti-VM results)
    hash = hash64(hash ^ client_state_hash);

    solution.solution = hash;
    solution.client_timestamp = static_cast<uint64_t>(std::time(nullptr));
    solution.client_state_hash = client_state_hash;
    solution.reserved = 0;

    return solution;
}

// Verify heartbeat solution on server side
template<KeyType K>
[[nodiscard]] inline bool verify_heartbeat_solution(
    const HeartbeatChallenge& challenge,
    const HeartbeatSolution& solution,
    const K& session_key,
    uint64_t server_time) noexcept
{
    // Recompute expected solution
    uint64_t hash = challenge.nonce;

    for (size_t i = 0; i < session_key.size(); ++i) {
        hash = hash64(hash ^ (static_cast<uint64_t>(session_key.data()[i]) << (i % 8)));
    }

    hash = hash64(hash ^ challenge.timestamp);
    hash = hash64(hash ^ challenge.session_id);

    for (uint32_t i = 0; i < challenge.difficulty; ++i) {
        hash = hash64(hash ^ i);
    }

    hash = hash64(hash ^ solution.client_state_hash);

    // Verify solution matches
    if (hash != solution.solution) {
        return false;
    }

    // Verify timing (must respond within reasonable window)
    // Too fast = precomputed, too slow = timeout
    if (solution.client_timestamp < challenge.timestamp) {
        return false;  // Clock went backwards - suspicious
    }

    uint64_t time_diff = solution.client_timestamp - challenge.timestamp;

    // Must take less than 5 seconds (includes proof-of-work computation time)
    if (time_diff > 5) {
        return false;
    }

    // Check server-side timing (network latency + computation)
    uint64_t server_diff = server_time > challenge.timestamp
        ? server_time - challenge.timestamp
        : 0;

    if (server_diff > 6) {  // 5s client timeout + 1s network latency
        return false;
    }

    return true;
}

} // namespace crypto
