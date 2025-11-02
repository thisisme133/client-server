#include "network.hpp"
#include "packet.hpp"
#include "crypto.hpp"
#include "compression.hpp"
#include "protected_function.hpp"
#include "protected_client_functions.hpp"

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
#include <mutex>
#include <atomic>
#include <iostream>
#include <ranges>
#include <algorithm>

using namespace std::chrono_literals;

namespace client {

inline constexpr std::string_view SERVER_IP = "127.0.0.1";
inline constexpr uint16_t SERVER_PORT = 8888;
inline constexpr auto CHALLENGE_TIMEOUT = 5s;
inline constexpr auto HEARTBEAT_INTERVAL = 5s;  // Send heartbeat every 5s max
inline constexpr auto HEARTBEAT_TIMEOUT = 10s;  // Disconnect if no challenge for 10s
inline constexpr auto RECONNECT_BASE_DELAY = 1s;
inline constexpr uint32_t MAX_RECONNECT_ATTEMPTS = 10;
inline constexpr uint32_t HEARTBEAT_DIFFICULTY = 100000;  // Proof-of-work iterations

// TODO: Add configurable server list (fallback servers)

class GameClient : public protect::FunctionRequester {
    net::Socket socket_;
    bool authenticated_ = false;
    std::array<uint8_t, proto::SESSION_KEY_SIZE> session_key_{};
    uint32_t current_challenge_ = 0;
    std::chrono::steady_clock::time_point challenge_time_;

    std::vector<uint8_t> pe_buffer_;
    uint32_t pe_entry_rva_ = 0;
    std::string target_process_;

    // Heartbeat system
    std::jthread heartbeat_thread_;
    std::mutex heartbeat_mutex_;
    std::mutex send_mutex_;  // Protect send_packet from concurrent access
    std::atomic<bool> running_{false};
    crypto::HeartbeatChallenge current_heartbeat_challenge_{};
    std::chrono::steady_clock::time_point last_heartbeat_challenge_received_;
    uint32_t session_id_ = 0;

    // Reconnection
    uint32_t reconnect_attempts_ = 0;

    // Statistics
    uint64_t bytes_sent_ = 0;
    uint64_t bytes_received_ = 0;
    uint64_t packets_processed_ = 0;

    // Connection quality metrics
    std::chrono::milliseconds avg_latency_{0};
    uint32_t packets_lost_ = 0;
    std::chrono::steady_clock::time_point last_ping_sent_;
    uint32_t ping_sequence_ = 0;

public:
    [[nodiscard]] auto connect() -> std::expected<void, net::Error> {
        auto result = net::connect(SERVER_IP, SERVER_PORT);
        if (!result) return std::unexpected(result.error());

        socket_ = std::move(*result);

        if (auto res = socket_.set_nonblocking(); !res) {
            return std::unexpected(res.error());
        }

        // Initialize heartbeat system
        auto now = std::chrono::steady_clock::now();
        last_heartbeat_challenge_received_ = now;
        running_ = true;
        session_id_ = static_cast<uint32_t>(std::time(nullptr));

        // Start heartbeat thread
        heartbeat_thread_ = std::jthread([this](std::stop_token stoken) {
            heartbeat_worker(stoken);
        });

        return send_connect();
    }

    void run() {
        std::array<uint8_t, 2048> buffer;

        while (socket_.valid() && running_) {
            auto now = std::chrono::steady_clock::now();

            // Check heartbeat challenge timeout - server must send challenges
            if (authenticated_ && now - last_heartbeat_challenge_received_ > HEARTBEAT_TIMEOUT) {
                std::cout << "Heartbeat timeout - no challenge from server\n";
                handle_disconnect();
                if (!try_reconnect()) break;
                continue;
            }

            auto received = socket_.recv(buffer);

            if (!received) {
                if (received.error() == net::Error::WouldBlock) {
                    std::this_thread::sleep_for(10ms);
                    continue;
                }
                handle_disconnect();
                if (!try_reconnect()) break;
                continue;
            }

            if (*received == 0) {
                std::this_thread::sleep_for(10ms);
                continue;
            }

            bytes_received_ += *received;
            process_data(std::span{buffer.data(), *received});
        }

        running_ = false;
    }

private:
    auto send_connect() -> std::expected<void, net::Error> {
        proto::Packet pkt{proto::PacketType::Connect};
        return send_packet(pkt, false);
    }

    auto send_packet(const proto::Packet& pkt, bool encrypt) -> std::expected<void, net::Error> {
        std::lock_guard lock(send_mutex_);  // Protect concurrent sends

        std::array<uint8_t, proto::MAX_PACKET_SIZE> buffer;
        uint16_t size = pkt.serialize(buffer);

        if (size == 0) {
            return std::unexpected(net::Error::SendFailed);
        }

        auto result = socket_.send(std::span{buffer.data(), size});
        if (result) {
            bytes_sent_ += *result;
        }
        return result.transform([](auto) {});
    }

    // Compute client state hash (anti-debug, anti-VM checks)
    // Uses protected functions from server to prevent tampering
    uint32_t compute_client_state_hash() const {
        uint32_t state = 0;

        // Call protected anti-debug function from server
        if (auto result = protect::FnProtectGlobal::Call<bool>(MARKER(check_debugger_present))) {
            state |= (*result ? 1 : 0) << 0;
        }

        // Call protected anti-VM function from server
        if (auto result = protect::FnProtectGlobal::Call<bool>(MARKER(check_vm_present))) {
            state |= (*result ? 1 : 0) << 1;
        }

        // Mix in some timing/entropy to make it harder to predict
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t nanos = now.time_since_epoch().count();
        state ^= static_cast<uint32_t>(nanos & 0xFFFFFFFF);

        return state;
    }

    // Heartbeat worker thread - runs in background
    void heartbeat_worker(std::stop_token stoken) {
        while (!stoken.stop_requested() && running_) {
            std::this_thread::sleep_for(100ms);

            if (!authenticated_ || !socket_.valid()) {
                continue;
            }

            // Check if we have a pending challenge to solve
            crypto::HeartbeatChallenge challenge;
            {
                std::lock_guard lock(heartbeat_mutex_);
                challenge = current_heartbeat_challenge_;
            }

            // If we have a valid challenge (nonce != 0), solve it
            if (challenge.nonce != 0) {
                // Compute client state
                uint32_t client_state = compute_client_state_hash();

                // Solve the challenge with proof-of-work
                auto solution = crypto::solve_heartbeat_challenge(
                    challenge, session_key_, client_state
                );

                // Send response
                proto::Packet pkt{proto::PacketType::HeartbeatResponse};
                auto* payload = pkt.payload_as<proto::PayloadHeartbeatResponse>();
                payload->solution = solution.solution;
                payload->client_timestamp = solution.client_timestamp;
                payload->client_state_hash = solution.client_state_hash;
                payload->reserved = 0;

                pkt.set_payload(*payload);
                send_packet(pkt, true);

                // Clear the challenge
                {
                    std::lock_guard lock(heartbeat_mutex_);
                    current_heartbeat_challenge_ = {};
                }
            }
        }
    }

    void handle_disconnect() {
        running_ = false;
        socket_ = {};
        authenticated_ = false;
    }

    bool try_reconnect() {
        if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
            return false;
        }

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, ...
        auto delay = RECONNECT_BASE_DELAY * (1 << reconnect_attempts_);
        std::this_thread::sleep_for(delay);

        reconnect_attempts_++;

        if (auto result = connect(); result) {
            reconnect_attempts_ = 0;
            return true;
        }

        return false;
    }

    void process_data(std::span<const uint8_t> data) {
        size_t offset = 0;

        while (offset < data.size()) {
            auto remaining = data.subspan(offset);
            auto packet_result = proto::Packet::deserialize(remaining);

            if (!packet_result) break;

            auto& packet = *packet_result;
            packets_processed_++;

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

            case HeartbeatChallenge: {
                auto* payload = packet.payload_as<proto::PayloadHeartbeatChallenge>();

                // Store the challenge for the heartbeat thread to solve
                {
                    std::lock_guard lock(heartbeat_mutex_);
                    current_heartbeat_challenge_.nonce = payload->nonce;
                    current_heartbeat_challenge_.timestamp = payload->timestamp;
                    current_heartbeat_challenge_.difficulty = payload->difficulty;
                    current_heartbeat_challenge_.session_id = payload->session_id;
                }

                last_heartbeat_challenge_received_ = std::chrono::steady_clock::now();
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

            case FunctionResponse: {
                auto* payload = packet.payload_as<proto::PayloadFunctionResponse>();
                handle_function_response(*payload);
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

        // Use protected functions from server for anti-debug/VM checks
        // This prevents tampering with the detection logic
        std::cout << "[Protected] Calling server-side anti-debug/VM checks...\n";
        payload->is_debugged = 0;
        payload->is_vm = 0;
        payload->is_suspended = 0;

        if (auto result = protect::FnProtectGlobal::Call<bool>(MARKER(check_debugger_present))) {
            payload->is_debugged = *result ? 1 : 0;
            std::cout << "[Protected] Debugger check: " << (*result ? "DETECTED" : "OK") << "\n";
        } else {
            std::cout << "[Protected] Failed to call check_debugger_present: " << result.error() << "\n";
        }

        if (auto result = protect::FnProtectGlobal::Call<bool>(MARKER(check_vm_present))) {
            payload->is_vm = *result ? 1 : 0;
            std::cout << "[Protected] VM check: " << (*result ? "DETECTED" : "OK") << "\n";
        } else {
            std::cout << "[Protected] Failed to call check_vm_present: " << result.error() << "\n";
        }

#ifdef _WIN32
        // Hide thread from debugger
        auto& mgr = shadow::SyscallManager::instance();
        mgr.set_information_thread(GetCurrentThread(), 0x11, nullptr, 0);  // ThreadHideFromDebugger
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

    // FunctionRequester interface implementation
    bool request_function(uint32_t marker_hash) override {
        proto::Packet pkt{proto::PacketType::FunctionRequest};
        auto* payload = pkt.payload_as<proto::PayloadFunctionRequest>();
        payload->marker_hash = marker_hash;
        payload->timestamp = static_cast<uint32_t>(std::time(nullptr));
        pkt.set_payload(*payload);

        return send_packet(pkt, true).has_value();
    }

    void handle_function_response(const proto::PayloadFunctionResponse& payload) {
        auto& storage = protect::BytecodeStorage::instance();

        // Extract function name (null-terminated)
        std::string_view function_name(payload.function_name.data());

        // Verify checksum BEFORE storing
        std::span<const uint8_t> code{payload.code.data(), payload.code_size};
        uint32_t received_checksum = payload.checksum;
        uint32_t computed_checksum = protect::simple_checksum(code);

        if (received_checksum != computed_checksum) {
            // Checksum mismatch - possible network corruption or MITM attack
            // Do NOT store corrupted bytecode
            return;
        }

        // Store bytecode with name for collision detection
        // RWX memory will be allocated temporarily during execution
        if (!storage.store(payload.marker_hash, function_name, code)) {
            // Hash collision detected or storage failed
            return;
        }

        // Notify pending request
        protect::PendingRequests::instance().complete(payload.marker_hash);
    }

#ifdef _WIN32
    void inject_pe() {
        std::cout << "[Protected] Using server-side PE injection logic\n";

        // Use protected inject_pe function from server
        // This hides the entire injection logic from the client binary
        std::string target = target_process_.empty() ? "notepad.exe" : target_process_;
        uint64_t base_address = 0;

        auto result = protect::FnProtectGlobal::Call<bool>(
            MARKER(inject_pe),
            pe_buffer_.data(),
            pe_buffer_.size(),
            pe_entry_rva_,
            target.c_str(),
            target.size(),
            &base_address
        );

        // Send completion
        proto::Packet pkt{proto::PacketType::PEComplete};
        auto* complete = pkt.payload_as<proto::PayloadPEComplete>();
        complete->success = (result && *result) ? 1 : 0;
        complete->base_address = base_address;
        pkt.set_payload(*complete);
        send_packet(pkt, true);

        if (result && *result) {
            std::cout << "[Protected] PE injected successfully at 0x" << std::hex << base_address << std::dec << "\n";
        } else {
            std::cout << "[Protected] PE injection failed\n";
        }
    }
#endif
};

} // namespace client

int main() {
    if (auto result = net::NetworkManager::instance().init(); !result) {
        return 1;
    }

    client::GameClient client;

    // Set up protected function system
    protect::FnProtectGlobal::set_requester(&client);

    if (auto result = client.connect(); !result) {
        return 1;
    }

    client.run();

    return 0;
}
