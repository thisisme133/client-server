#include "packet.hpp"
#include "crypto.hpp"
#include <cstring>

namespace proto {

uint16_t Packet::serialize(std::span<uint8_t> buffer) const noexcept {
    if (buffer.size() < sizeof(PacketHeader) + header.length) {
        return 0;
    }

    // Copy header
    std::memcpy(buffer.data(), &header, sizeof(PacketHeader));

    // Copy payload
    if (header.length > 0) {
        std::memcpy(buffer.data() + sizeof(PacketHeader), payload.data(), header.length);
    }

    return sizeof(PacketHeader) + header.length;
}

std::expected<Packet, std::string_view>
Packet::deserialize(std::span<const uint8_t> buffer) noexcept {
    if (buffer.size() < sizeof(PacketHeader)) {
        return std::unexpected("Buffer too small for header");
    }

    Packet packet;
    std::memcpy(&packet.header, buffer.data(), sizeof(PacketHeader));

    if (!packet.header.valid()) {
        return std::unexpected("Invalid packet magic or version");
    }

    if (packet.header.length > MAX_PAYLOAD_SIZE) {
        return std::unexpected("Payload too large");
    }

    if (buffer.size() < sizeof(PacketHeader) + packet.header.length) {
        return std::unexpected("Buffer too small for payload");
    }

    // Copy payload
    if (packet.header.length > 0) {
        std::memcpy(packet.payload.data(), buffer.data() + sizeof(PacketHeader),
                   packet.header.length);
    }

    return packet;
}

} // namespace proto
