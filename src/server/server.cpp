#include "network.hpp"
#include "packet.hpp"
#include "crypto.hpp"
#include "compression.hpp"
#include "function_storage.hpp"

#include <thread>
#include <mutex>
#include <array>
#include <vector>
#include <unordered_map>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <ranges>
#include <algorithm>

using namespace std::chrono_literals;

namespace server {

inline constexpr uint16_t PORT = 8888;
inline constexpr size_t MAX_CLIENTS = 32;
inline constexpr size_t PE_CHUNK_COUNT = 150;

// TODO: Load configuration from file (port, max_clients, timeout values)
// TODO: Add rate limiting per client (packets per second, bandwidth)
// TODO: Add logging system (connection events, errors, injections)
// TODO: Add admin interface for monitoring and control

struct GameInfo {
    uint32_t id;
    std::string name;
    std::filesystem::path dll_path;
    std::string target_process;

    // TODO: Add version field for PE versioning
    // TODO: Add checksum/signature for integrity verification
    // TODO: Add encryption key for PE encryption at rest
};

class ClientSession {
    net::Socket socket_;
    uint8_t id_;
    bool authenticated_ = false;
    std::array<uint8_t, proto::SESSION_KEY_SIZE> session_key_{};
    uint32_t challenge_ = 0;
    std::string ip_;

    // TODO: Add last_activity_ timestamp for idle timeout detection
    // TODO: Add connection_time_ for session duration tracking
    // TODO: Add statistics (packets_sent, packets_received, bytes_transferred)
    // TODO: Add rate_limiter for packet flood protection
    // TODO: Add reconnection token for session resumption

public:
    explicit ClientSession(uint8_t id, net::Socket socket, std::string ip)
        : socket_(std::move(socket)), id_(id), ip_(std::move(ip)) {

        socket_.set_nonblocking();
        send_challenge();
    }

    [[nodiscard]] bool active() const { return socket_.valid(); }
    [[nodiscard]] uint8_t id() const { return id_; }

    void process() {
        std::array<uint8_t, 2048> buffer;

        auto received = socket_.recv(buffer);
        if (!received) {
            if (received.error() != net::Error::WouldBlock) {
                socket_ = {};
            }
            return;
        }

        if (*received > 0) {
            handle_data(std::span{buffer.data(), *received});
        }
    }

private:
    void send_challenge() {
        proto::Packet pkt{proto::PacketType::Challenge};
        auto* payload = pkt.payload_as<proto::PayloadChallenge>();

        challenge_ = static_cast<uint32_t>(std::random_device{}());
        payload->challenge = challenge_;
        payload->timestamp = static_cast<uint32_t>(std::time(nullptr));

        pkt.set_payload(*payload);
        send_packet(pkt, false);
    }

    void send_packet(const proto::Packet& pkt, bool encrypt) {
        std::array<uint8_t, proto::MAX_PACKET_SIZE> buffer;
        uint16_t size = pkt.serialize(buffer);

        if (size > 0) {
            socket_.send(std::span{buffer.data(), size});
        }
    }

    void handle_data(std::span<const uint8_t> data) {
        size_t offset = 0;

        while (offset < data.size()) {
            auto remaining = data.subspan(offset);
            auto packet_result = proto::Packet::deserialize(remaining);

            if (!packet_result) break;

            handle_packet(*packet_result);
            offset += sizeof(proto::PacketHeader) + packet_result->length();
        }
    }

    void handle_packet(proto::Packet& packet) {
        using enum proto::PacketType;

        if (packet.has_flag(proto::PacketFlags::Encrypted) && authenticated_) {
            crypto::decrypt(session_key_, packet.payload_view(), packet.payload_view());
        }

        switch (packet.type()) {
            case ChallengeResponse: {
                auto* payload = packet.payload_as<proto::PayloadChallengeResponse>();

                // TODO: Add challenge timeout verification (reject if too slow/fast)
                // TODO: Add challenge replay protection (store used challenges)
                // TODO: Add brute-force protection (max attempts per IP)

                uint32_t expected = crypto::solve_challenge(challenge_);
                if (payload->challenge_solution != expected) {
                    // TODO: Log failed authentication attempt with IP and timestamp
                    // TODO: Increment failed_attempts counter for blacklisting
                    socket_ = {};
                    return;
                }

                // Check anti-debug flags
                // TODO: Make anti-debug checks configurable per game
                // TODO: Add whitelist for authorized debuggers (development mode)
                // TODO: Add additional integrity checks (module hashes, imports)
                if (payload->is_debugged || payload->is_vm || payload->is_suspended) {
                    // TODO: Log security violation with details
                    socket_ = {};
                    return;
                }

                send_session_key();
                break;
            }

            case Connect: {
                authenticated_ = true;
                send_game_list();
                break;
            }

            case GameSelect: {
                auto* payload = packet.payload_as<proto::PayloadGameSelect>();
                handle_game_select(payload->game_id);
                break;
            }

            case FunctionRequest: {
                auto* payload = packet.payload_as<proto::PayloadFunctionRequest>();
                handle_function_request(payload->marker_hash);
                break;
            }

            default:
                break;
        }
    }

    void send_session_key() {
        proto::Packet pkt{proto::PacketType::SessionKey};
        auto* payload = pkt.payload_as<proto::PayloadSessionKey>();

        std::random_device rd;
        std::generate(session_key_.begin(), session_key_.end(), [&rd] { return static_cast<uint8_t>(rd()); });

        payload->key = session_key_;
        pkt.set_payload(*payload);
        send_packet(pkt, false);
    }

    void send_game_list() {
        proto::Packet pkt{proto::PacketType::GameList};
        auto* payload = pkt.payload_as<proto::PayloadGameList>();

        payload->count = 3;
        std::strcpy(payload->games[0].data(), "Counter-Strike 2");
        std::strcpy(payload->games[1].data(), "Valorant");
        std::strcpy(payload->games[2].data(), "Apex Legends");

        pkt.set_payload(*payload);
        send_packet(pkt, true);
    }

    void handle_game_select([[maybe_unused]] uint32_t game_id) {
        // TODO: Implement real PE loading from disk:
        //  - Load from GameInfo[game_id].dll_path
        //  - Validate PE file integrity (signature, checksum)
        //  - Encrypt PE data before transmission
        //  - Compress PE data for bandwidth optimization
        //
        // TODO: Add access control:
        //  - Check client subscription/license for game_id
        //  - Verify client privileges and permissions
        //  - Rate limit PE downloads per client
        //
        // TODO: Add PE streaming optimization:
        //  - Implement adaptive chunk sizing based on network conditions
        //  - Add chunk acknowledgments and retransmission
        //  - Add checksum per chunk for integrity verification

        // Load PE file (simplified demo)
        std::vector<uint8_t> pe_data(4096, 0xCC);  // Demo: INT3 instructions

        // Stream in chunks
        size_t chunk_size = (pe_data.size() + PE_CHUNK_COUNT - 1) / PE_CHUNK_COUNT;

        for (size_t i = 0; i < PE_CHUNK_COUNT; ++i) {
            proto::Packet pkt{proto::PacketType::PEChunk};
            auto* payload = pkt.payload_as<proto::PayloadPEChunk>();

            payload->chunk_index = i;
            payload->total_chunks = PE_CHUNK_COUNT;
            payload->total_size = pe_data.size();
            payload->entry_rva = 0x1000;

            size_t offset = i * chunk_size;
            size_t remaining = std::min(chunk_size, pe_data.size() - offset);

            payload->chunk_size = remaining;
            std::memcpy(payload->data.data(), pe_data.data() + offset, remaining);

            pkt.set_payload(*payload);
            send_packet(pkt, true);

            std::this_thread::sleep_for(1ms);
        }
    }

    void handle_function_request(uint32_t marker_hash) {
        auto& storage = FunctionStorage::instance();

        // Check if function exists
        if (!storage.has_function(marker_hash)) {
            // Function not found, could send error
            return;
        }

        // Get function bytecode
        auto code = storage.get_function_code(marker_hash);
        if (code.empty()) return;

        // Send function response
        proto::Packet pkt{proto::PacketType::FunctionResponse};
        auto* payload = pkt.payload_as<proto::PayloadFunctionResponse>();
        payload->marker_hash = marker_hash;
        payload->code_size = std::min(code.size(), payload->code.size());
        std::memcpy(payload->code.data(), code.data(), payload->code_size);
        pkt.set_payload(*payload);
        send_packet(pkt, true);
    }
};

class GameServer {
    net::Socket listen_socket_;
    std::vector<std::unique_ptr<ClientSession>> clients_;
    std::vector<std::jthread> client_threads_;
    std::mutex clients_mutex_;

public:
    [[nodiscard]] auto start() -> std::expected<void, net::Error> {
        auto socket_result = net::create_socket();
        if (!socket_result) return std::unexpected(socket_result.error());

        listen_socket_ = std::move(*socket_result);

        if (auto result = net::bind(listen_socket_.get(), PORT); !result) {
            return std::unexpected(result.error());
        }

        if (auto result = net::listen(listen_socket_.get(), MAX_CLIENTS); !result) {
            return std::unexpected(result.error());
        }

        if (auto result = listen_socket_.set_nonblocking(); !result) {
            return std::unexpected(result.error());
        }

        return {};
    }

    void run() {
        while (listen_socket_.valid()) {
            std::array<char, 46> ip;
            uint16_t port;

            auto client_result = net::accept(listen_socket_.get(), ip, port);

            if (client_result) {
                std::lock_guard lock(clients_mutex_);

                auto id = find_free_slot();
                if (id < MAX_CLIENTS) {
                    auto session = std::make_unique<ClientSession>(
                        id, std::move(*client_result), std::string{ip.data()}
                    );

                    client_threads_.emplace_back([session = session.get()] {
                        while (session->active()) {
                            session->process();
                            std::this_thread::sleep_for(10ms);
                        }
                    });

                    clients_.push_back(std::move(session));
                }
            }

            std::this_thread::sleep_for(10ms);
        }
    }

private:
    [[nodiscard]] uint8_t find_free_slot() const {
        for (uint8_t i = 0; i < MAX_CLIENTS; ++i) {
            auto it = std::ranges::find_if(clients_, [i](const auto& client) {
                return client && client->id() == i;
            });

            if (it == clients_.end()) {
                return i;
            }
        }
        return MAX_CLIENTS;
    }
};

} // namespace server

int main() {
    if (auto result = net::NetworkManager::instance().init(); !result) {
        return 1;
    }

    server::GameServer server;

    if (auto result = server.start(); !result) {
        return 1;
    }

    server.run();

    return 0;
}
