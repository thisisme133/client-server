#pragma once

#include <cstdint>
#include <array>
#include <span>
#include <concepts>
#include <bit>
#include <string_view>
#include <expected>
#include <utility>
#include <cstring>

namespace proto {

// Compile-time constants
inline constexpr uint16_t MAX_PACKET_SIZE = 2048;
inline constexpr uint16_t MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - 16;
inline constexpr uint32_t PACKET_MAGIC = 0xDEADBEEF;
inline constexpr uint16_t PROTOCOL_VERSION = 1;
inline constexpr uint8_t SESSION_KEY_SIZE = 32;

// Packet types
enum class PacketType : uint8_t {
    Connect = 0,
    Disconnect,
    Challenge,
    ChallengeResponse,
    SessionKey,
    Ack,
    Error,
    GameList,
    GameSelect,
    PEChunk,
    PEComplete,
    FunctionRequest,   // Client requests a protected function
    FunctionResponse   // Server sends function code
};

// Packet flags
enum class PacketFlags : uint8_t {
    None = 0,
    Encrypted = 1 << 0,
    Compressed = 1 << 1
};

constexpr PacketFlags operator|(PacketFlags a, PacketFlags b) noexcept {
    return static_cast<PacketFlags>(std::to_underlying(a) | std::to_underlying(b));
}

constexpr PacketFlags operator&(PacketFlags a, PacketFlags b) noexcept {
    return static_cast<PacketFlags>(std::to_underlying(a) & std::to_underlying(b));
}

constexpr bool has_flag(PacketFlags flags, PacketFlags flag) noexcept {
    return (flags & flag) == flag;
}

// Packet header (fixed size, optimized layout)
struct alignas(8) PacketHeader {
    uint32_t magic = PACKET_MAGIC;
    uint16_t version = PROTOCOL_VERSION;
    uint16_t length = 0;
    PacketType type = PacketType::Connect;
    PacketFlags flags = PacketFlags::None;
    uint16_t sequence = 0;
    uint32_t crc32 = 0;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return magic == PACKET_MAGIC && version == PROTOCOL_VERSION;
    }
};

static_assert(sizeof(PacketHeader) == 16, "Header must be 16 bytes");

// Packet structure
struct Packet {
    PacketHeader header;
    std::array<uint8_t, MAX_PAYLOAD_SIZE> payload{};

    constexpr Packet() noexcept = default;
    explicit constexpr Packet(PacketType type) noexcept {
        header.type = type;
    }

    [[nodiscard]] constexpr PacketType type() const noexcept { return header.type; }
    [[nodiscard]] constexpr uint16_t length() const noexcept { return header.length; }
    [[nodiscard]] constexpr bool has_flag(PacketFlags flag) const noexcept {
        return proto::has_flag(header.flags, flag);
    }

    constexpr void set_flag(PacketFlags flag) noexcept {
        header.flags = header.flags | flag;
    }

    constexpr void clear_flag(PacketFlags flag) noexcept {
        header.flags = static_cast<PacketFlags>(
            std::to_underlying(header.flags) & ~std::to_underlying(flag)
        );
    }

    [[nodiscard]] constexpr std::span<uint8_t> payload_view() noexcept {
        return {payload.data(), header.length};
    }

    [[nodiscard]] constexpr std::span<const uint8_t> payload_view() const noexcept {
        return {payload.data(), header.length};
    }

    // Template for type-safe payload access
    template<typename T>
    [[nodiscard]] constexpr T* payload_as() noexcept {
        static_assert(sizeof(T) <= MAX_PAYLOAD_SIZE);
        return std::bit_cast<T*>(payload.data());
    }

    template<typename T>
    [[nodiscard]] constexpr const T* payload_as() const noexcept {
        static_assert(sizeof(T) <= MAX_PAYLOAD_SIZE);
        return std::bit_cast<const T*>(payload.data());
    }

    template<typename T>
    constexpr void set_payload(const T& data) noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        static_assert(sizeof(T) <= MAX_PAYLOAD_SIZE);
        std::memcpy(payload.data(), &data, sizeof(T));
        header.length = sizeof(T);
    }

    // Serialization
    [[nodiscard]] uint16_t serialize(std::span<uint8_t> buffer) const noexcept;
    [[nodiscard]] static std::expected<Packet, std::string_view>
        deserialize(std::span<const uint8_t> buffer) noexcept;
};

// Payload structures (POD for network transmission)
struct PayloadChallenge {
    uint32_t challenge;
    uint32_t timestamp;
};

struct PayloadChallengeResponse {
    uint32_t challenge_solution;
    uint8_t is_debugged;
    uint8_t is_vm;
    uint8_t is_suspended;
    uint8_t reserved;
};

struct PayloadSessionKey {
    std::array<uint8_t, SESSION_KEY_SIZE> key;
};

struct PayloadGameList {
    uint32_t count;
    std::array<std::array<char, 64>, 16> games;
};

struct PayloadGameSelect {
    uint32_t game_id;
};

struct PayloadPEChunk {
    uint32_t chunk_index;
    uint32_t total_chunks;
    uint32_t chunk_size;
    uint32_t total_size;
    uint32_t entry_rva;
    std::array<uint8_t, MAX_PAYLOAD_SIZE - 20> data;
};

struct PayloadPEComplete {
    uint8_t success;
    uint8_t reserved[3];
    uint32_t thread_id;
    uint64_t base_address;
};

struct PayloadFunctionRequest {
    uint32_t marker_hash;  // FNV1a hash of function name
    uint32_t timestamp;
};

struct PayloadFunctionResponse {
    uint32_t marker_hash;
    uint32_t code_size;
    std::array<uint8_t, MAX_PAYLOAD_SIZE - 8> code;
};

// Utilities
[[nodiscard]] constexpr bool should_compress(std::span<const uint8_t> data) noexcept {
    return data.size() > 256;
}

} // namespace proto
