#include "network.hpp"
#include "packet.hpp"
#include "crypto.hpp"
#include "compression.hpp"
#include "protected_client_functions.hpp"

#ifdef _WIN32
#include "syscalls.hpp"
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#endif

#include <array>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <ranges>
#include <algorithm>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <memory>
#include <cstring>
#include <string_view>
#include <span>

using namespace std::chrono_literals;

namespace client
{
	/*
	   ========================================================================
	   PROTECTED FUNCTIONS SYSTEM - Integrated directly in client
	   ========================================================================
	*/

	namespace protect
	{
		/**
		 * @brief compile-time FNV-1a hash for function markers
		 */
		constexpr auto fnv1a_hash( std::string_view str ) noexcept -> uint32_t
		{
			uint32_t hash{ 2166136261u };
			for ( char c : str )
			{
				hash ^= static_cast<uint32_t>( c );
				hash *= 16777619u;
			}
			return hash;
		}

		/**
		 * @brief function marker
		 */
		struct function_marker_t
		{
			uint32_t hash{ };
			std::string_view name{ };

			constexpr function_marker_t( std::string_view n ) noexcept
				: hash{ fnv1a_hash( n ) }, name{ n }
			{
			}
		};

		/**
		 * @brief temporary function executor
		 */
		class temporary_function_t
		{
			void* m_exec_memory{ nullptr };
			size_t m_size{ 0 };

		public:
			explicit temporary_function_t( std::span<const uint8_t> bytecode ) : m_size{ bytecode.size( ) }
			{
				if ( bytecode.empty( ) ) return;

#ifdef _WIN32
				m_exec_memory = VirtualAlloc( nullptr, m_size,
				                              MEM_COMMIT | MEM_RESERVE,
				                              PAGE_EXECUTE_READWRITE );
				if ( m_exec_memory )
				{
					std::memcpy( m_exec_memory, bytecode.data( ), m_size );
				}
#else
				m_exec_memory = mmap( nullptr, m_size,
				                      PROT_READ | PROT_WRITE | PROT_EXEC,
				                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
				if ( m_exec_memory != MAP_FAILED )
				{
					std::memcpy( m_exec_memory, bytecode.data( ), m_size );
				}
				else
				{
					m_exec_memory = nullptr;
				}
#endif
			}

			~temporary_function_t( )
			{
				if ( m_exec_memory )
				{
#ifdef _WIN32
					VirtualFree( m_exec_memory, 0, MEM_RELEASE );
#else
					munmap( m_exec_memory, m_size );
#endif
				}
			}

			temporary_function_t( const temporary_function_t& ) = delete;
			auto operator=( const temporary_function_t& ) -> temporary_function_t& = delete;

			template<typename Ret, typename... Args>
			auto execute( Args&&... args ) const -> Ret
			{
				if ( !m_exec_memory )
				{
					if constexpr ( std::is_same_v<Ret, bool> ) return false;
					else if constexpr ( std::is_arithmetic_v<Ret> ) return static_cast<Ret>( 0 );
					else return Ret{ };
				}

				using fn_ptr = Ret( * )( Args... );
				auto fn{ reinterpret_cast<fn_ptr>( m_exec_memory ) };
				return fn( std::forward<Args>( args )... );
			}

			[[nodiscard]] auto valid( ) const noexcept -> bool
			{
				return m_exec_memory != nullptr;
			}
		};

	} // namespace protect

	/*
	   client-side protection system (bytecode storage and execution)
	*/

	/**
	 * @brief simple checksum for bytecode integrity
	 * @param data bytecode data
	 * @return checksum value
	 */
	inline constexpr auto simple_checksum( std::span<const uint8_t> data ) noexcept -> uint32_t
	{
		uint32_t checksum{ 0x5A5A5A5A };
		for ( size_t i{ 0 }; i < data.size( ); ++i )
		{
			checksum ^= data[i];
			checksum = ( checksum << 7 ) | ( checksum >> 25 );
			checksum += i * 0x01000193;
		}
		return checksum;
	}

	/**
	 * @brief bytecode storage with integrity verification
	 */
	class bytecode_storage_t
	{
		struct bytecode_entry_t
		{
			std::string name{ };
			std::vector<uint8_t> code{ };
			uint32_t checksum{ };
			size_t expected_size{ };
		};

		std::unordered_map<uint32_t, bytecode_entry_t> m_storage{ };
		std::mutex m_mutex{ };

		bytecode_storage_t( ) = default;

	public:
		static auto instance( ) -> bytecode_storage_t&
		{
			static bytecode_storage_t storage{ };
			return storage;
		}

		auto store( uint32_t marker_hash, std::string_view name, std::span<const uint8_t> code ) -> bool
		{
			std::lock_guard lock{ m_mutex };

			auto it{ m_storage.find( marker_hash ) };
			if ( it != m_storage.end( ) && it->second.name != name )
			{
				return false;
			}

			bytecode_entry_t entry{ };
			entry.name = std::string( name );
			entry.code = std::vector<uint8_t>( code.begin( ), code.end( ) );
			entry.checksum = simple_checksum( code );
			entry.expected_size = code.size( );

			m_storage[marker_hash] = std::move( entry );
			return true;
		}

		auto get( uint32_t marker_hash, std::string_view expected_name ) -> std::vector<uint8_t>
		{
			std::lock_guard lock{ m_mutex };
			auto it{ m_storage.find( marker_hash ) };

			if ( it == m_storage.end( ) )
			{
				return { };
			}

			auto& entry{ it->second };

			if ( entry.name != expected_name )
			{
				return { };
			}

			uint32_t actual_checksum{ simple_checksum( entry.code ) };
			if ( actual_checksum != entry.checksum )
			{
				m_storage.erase( it );
				return { };
			}

			if ( entry.code.size( ) != entry.expected_size )
			{
				m_storage.erase( it );
				return { };
			}

			return entry.code;
		}

		auto has( uint32_t marker_hash, std::string_view expected_name ) -> bool
		{
			std::lock_guard lock{ m_mutex };
			auto it{ m_storage.find( marker_hash ) };
			return it != m_storage.end( ) && it->second.name == expected_name;
		}

		auto clear( ) -> void
		{
			std::lock_guard lock{ m_mutex };
			m_storage.clear( );
		}
	};

	/**
	 * @brief pending function requests manager
	 */
	class pending_requests_t
	{
		struct request_t
		{
			uint32_t marker_hash{ };
			std::mutex mutex{ };
			std::condition_variable cv{ };
			bool completed{ false };
		};

		std::unordered_map<uint32_t, std::shared_ptr<request_t>> m_requests{ };
		std::mutex m_mutex{ };

		pending_requests_t( ) = default;

	public:
		static auto instance( ) -> pending_requests_t&
		{
			static pending_requests_t pending{ };
			return pending;
		}

		auto add( uint32_t marker_hash ) -> std::shared_ptr<request_t>
		{
			std::lock_guard lock{ m_mutex };
			auto req{ std::make_shared<request_t>( ) };
			req->marker_hash = marker_hash;
			m_requests[marker_hash] = req;
			return req;
		}

		auto complete( uint32_t marker_hash ) -> void
		{
			std::shared_ptr<request_t> req{ };
			{
				std::lock_guard lock{ m_mutex };
				auto it{ m_requests.find( marker_hash ) };
				if ( it != m_requests.end( ) )
				{
					req = it->second;
					m_requests.erase( it );
				}
			}

			if ( req )
			{
				std::lock_guard lock{ req->mutex };
				req->completed = true;
				req->cv.notify_all( );
			}
		}

		auto remove( uint32_t marker_hash ) -> void
		{
			std::lock_guard lock{ m_mutex };
			m_requests.erase( marker_hash );
		}

		auto wait_for( uint32_t marker_hash, std::chrono::milliseconds timeout ) -> bool
		{
			std::shared_ptr<request_t> req{ };
			{
				std::lock_guard lock{ m_mutex };
				auto it{ m_requests.find( marker_hash ) };
				if ( it != m_requests.end( ) )
				{
					req = it->second;
				}
			}

			if ( !req ) return false;

			std::unique_lock lock{ req->mutex };
			bool success{ req->cv.wait_for( lock, timeout, [&] { return req->completed; } ) };

			{
				std::lock_guard map_lock{ m_mutex };
				auto it{ m_requests.find( marker_hash ) };
				if ( it != m_requests.end( ) && !it->second->completed )
				{
					m_requests.erase( it );
				}
			}

			return success;
		}
	};

	/**
	 * @brief function requester interface
	 */
	class function_requester_t
	{
	public:
		virtual ~function_requester_t( ) = default;
		virtual auto request_function( uint32_t marker_hash ) -> bool = 0;
	};

	/**
	 * @brief global protected function caller
	 */
	class protected_function_caller_t
	{
		static inline function_requester_t* m_requester{ nullptr };

	public:
		/**
		 * @brief set function requester
		 * @param req requester instance
		 */
		static auto set_requester( function_requester_t* req ) -> void
		{
			m_requester = req;
		}

		/**
		 * @brief call protected function
		 * @tparam Ret return type
		 * @tparam Args argument types
		 * @param marker function marker
		 * @param args function arguments
		 * @return function result or default value on error
		 */
		template<typename Ret, typename... Args>
		static auto call( protect::function_marker_t marker, Args&&... args ) -> Ret
		{
			auto& storage{ bytecode_storage_t::instance( ) };

			/*
			   check if bytecode is in storage
			*/
			std::vector<uint8_t> bytecode{ storage.get( marker.hash, marker.name ) };

			/*
			   if not in storage, request from server
			*/
			if ( bytecode.empty( ) )
			{
				if ( !m_requester )
				{
					if constexpr ( std::is_same_v<Ret, bool> )
					{
						return false;
					}
					else if constexpr ( std::is_arithmetic_v<Ret> )
					{
						return static_cast<Ret>( 0 );
					}
					else
					{
						return Ret{ };
					}
				}

				/*
				   add pending request
				*/
				auto& pending{ pending_requests_t::instance( ) };
				auto req{ pending.add( marker.hash ) };

				/*
				   request function from server
				*/
				if ( !m_requester->request_function( marker.hash ) )
				{
					pending.remove( marker.hash );
					if constexpr ( std::is_same_v<Ret, bool> )
					{
						return false;
					}
					else if constexpr ( std::is_arithmetic_v<Ret> )
					{
						return static_cast<Ret>( 0 );
					}
					else
					{
						return Ret{ };
					}
				}

				/*
				   wait for response (5 seconds timeout)
				*/
				if ( !pending.wait_for( marker.hash, std::chrono::seconds( 5 ) ) )
				{
					if constexpr ( std::is_same_v<Ret, bool> )
					{
						return false;
					}
					else if constexpr ( std::is_arithmetic_v<Ret> )
					{
						return static_cast<Ret>( 0 );
					}
					else
					{
						return Ret{ };
					}
				}

				/*
				   get bytecode from storage
				*/
				bytecode = storage.get( marker.hash, marker.name );
				if ( bytecode.empty( ) )
				{
					if constexpr ( std::is_same_v<Ret, bool> )
					{
						return false;
					}
					else if constexpr ( std::is_arithmetic_v<Ret> )
					{
						return static_cast<Ret>( 0 );
					}
					else
					{
						return Ret{ };
					}
				}
			}

			/*
			   sanity checks
			*/
			if ( bytecode.size( ) > 1024 * 1024 || bytecode.size( ) < 4 )
			{
				if constexpr ( std::is_same_v<Ret, bool> )
				{
					return false;
				}
				else if constexpr ( std::is_arithmetic_v<Ret> )
				{
					return static_cast<Ret>( 0 );
				}
				else
				{
					return Ret{ };
				}
			}

			/*
			   allocate executable memory temporarily (RAII - freed on scope exit)
			*/
			protect::temporary_function_t temp_fn{ bytecode };

			if ( !temp_fn.valid( ) )
			{
				if constexpr ( std::is_same_v<Ret, bool> )
				{
					return false;
				}
				else if constexpr ( std::is_arithmetic_v<Ret> )
				{
					return static_cast<Ret>( 0 );
				}
				else
				{
					return Ret{ };
				}
			}

			/*
			   execute function - memory will be freed automatically
			*/
			return temp_fn.execute<Ret>( std::forward<Args>( args )... );
		}
	};

	/*
	   ========================================================================
	   MACRO POUR APPELER LES FONCTIONS PROTÉGÉES
	   ========================================================================
	*/

	/**
	 * @brief macro pour appeler une fonction protégée
	 * @param RetType type de retour
	 * @param Name nom de la fonction
	 * @param ... arguments de la fonction
	 *
	 * Utilisation:
	 *   bool is_debugged = CALL_PROTECTED(bool, check_debugger_present);
	 *   uint32_t pid = CALL_PROTECTED(uint32_t, find_process_by_name, "notepad.exe", 12);
	 */
	#define CALL_PROTECTED(RetType, Name, ...) \
		client::protected_function_caller_t::call<RetType>( \
			client::protect::function_marker_t{ #Name }, \
			##__VA_ARGS__ \
		)

	/*
	   client constants
	*/
	inline constexpr std::string_view SERVER_IP{ "127.0.0.1" };
	inline constexpr uint16_t SERVER_PORT{ 8888 };
	inline constexpr auto CHALLENGE_TIMEOUT{ 5s };
	inline constexpr auto HEARTBEAT_INTERVAL{ 30s };
	inline constexpr auto HEARTBEAT_TIMEOUT{ 60s };
	inline constexpr auto RECONNECT_BASE_DELAY{ 1s };
	inline constexpr uint32_t MAX_RECONNECT_ATTEMPTS{ 10 };

	// TODO: Add configurable server list (fallback servers)

	/**
	 * @brief game client implementation
	 */
	class game_client_t : public function_requester_t
	{
    net::socket_wrapper_t socket_;
    bool authenticated_ = false;
    std::array<uint8_t, proto::SESSION_KEY_SIZE> session_key_{};
    uint32_t current_challenge_ = 0;
    std::chrono::steady_clock::time_point challenge_time_;

    std::vector<uint8_t> pe_buffer_;
    uint32_t pe_entry_rva_ = 0;
    std::string target_process_;

    // Heartbeat & reconnection
    std::chrono::steady_clock::time_point last_heartbeat_sent_;
    std::chrono::steady_clock::time_point last_heartbeat_received_;
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
    [[nodiscard]] auto connect() -> std::expected<void, net::error_t> {
        auto result = net::connect(SERVER_IP, SERVER_PORT);
        if (!result) return std::unexpected(result.error());

        socket_ = std::move(*result);

        if (auto res = socket_.set_nonblocking(); !res) {
            return std::unexpected(res.error());
        }

        // Initialize heartbeat timestamps
        auto now = std::chrono::steady_clock::now();
        last_heartbeat_sent_ = now;
        last_heartbeat_received_ = now;

        return send_connect();
    }

    void run() {
        std::array<uint8_t, 2048> buffer;

        while (socket_.valid()) {
            auto now = std::chrono::steady_clock::now();

            // Check heartbeat timeout
            if (now - last_heartbeat_received_ > HEARTBEAT_TIMEOUT) {
                handle_disconnect();
                if (!try_reconnect()) break;
                continue;
            }

            // Send heartbeat if needed
            if (now - last_heartbeat_sent_ > HEARTBEAT_INTERVAL) {
                send_heartbeat();
            }

            auto received = socket_.recv(buffer);

            if (!received) {
                if (received.error() == net::error_t::would_block) {
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
            last_heartbeat_received_ = now;
            process_data(std::span{buffer.data(), *received});
        }
    }

private:
    auto send_connect() -> std::expected<void, net::error_t> {
        proto::packet_t pkt{proto::packet_type_t::connect};
        return send_packet(pkt, false);
    }

    auto send_packet(const proto::packet_t& pkt, bool encrypt) -> std::expected<void, net::error_t> {
        std::array<uint8_t, proto::MAX_PACKET_SIZE> buffer;
        uint16_t size = pkt.serialize(buffer);

        if (size == 0) {
            return std::unexpected(net::error_t::send_failed);
        }

        auto result = socket_.send(std::span{buffer.data(), size});
        if (result) {
            bytes_sent_ += *result;
        }
        return result.transform([](auto) {});
    }

    void send_heartbeat() {
        proto::packet_t pkt{proto::packet_type_t::ack};
        send_packet(pkt, false);
        last_heartbeat_sent_ = std::chrono::steady_clock::now();
    }

    void handle_disconnect() {
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
            auto packet_result = proto::packet_t::deserialize(remaining);

            if (!packet_result) break;

            auto& packet = *packet_result;
            packets_processed_++;

            if (packet.has_flag(proto::packet_flags_t::encrypted) && authenticated_) {
                crypto::decrypt(session_key_, packet.payload_view(), packet.payload_view());
            }

            if (packet.has_flag(proto::packet_flags_t::compressed)) {
                std::array<uint8_t, proto::MAX_PAYLOAD_SIZE> decompressed;
                if (auto result = compression::rle_t::decompress(packet.payload_view(),
                                                              decompressed)) {
                    std::memcpy(packet.payload.data(), decompressed.data(), *result);
                    packet.header.length = *result;
                }
            }

            handle_packet(packet);
            offset += sizeof(proto::packet_header_t) + packet.length();
        }
    }

    void handle_packet(const proto::packet_t& packet) {
        using enum proto::packet_type_t;

        switch (packet.type()) {
            case challenge: {
                auto* payload = packet.payload_as<proto::payload_challenge_t>();
                current_challenge_ = payload->challenge;
                challenge_time_ = std::chrono::steady_clock::now();
                send_challenge_response();
                break;
            }

            case session_key: {
                auto* payload = packet.payload_as<proto::payload_session_key_t>();
                session_key_ = payload->key;
                authenticated_ = true;
                break;
            }

            case game_list: {
                auto* payload = packet.payload_as<proto::payload_game_list_t>();
                handle_game_list(*payload);
                break;
            }

            case pe_chunk: {
                auto* payload = packet.payload_as<proto::payload_pe_chunk_t>();
                handle_pe_chunk(*payload);
                break;
            }

            case function_response: {
                auto* payload = packet.payload_as<proto::payload_function_response_t>();
                handle_function_response(*payload);
                break;
            }

            default:
                break;
        }
    }

    void send_challenge_response() {
        proto::packet_t pkt{proto::packet_type_t::challenge_response};
        auto* payload = pkt.payload_as<proto::payload_challenge_response_t>();

        payload->challenge_solution = crypto::solve_challenge(current_challenge_);

#ifdef _WIN32
        payload->is_debugged = CALL_PROTECTED(bool, check_debugger_present) ? 1 : 0;
        payload->is_vm = CALL_PROTECTED(bool, check_vm_present) ? 1 : 0;
        payload->is_suspended = 0;  // Could check for suspended threads

        // Hide thread from debugger
        auto& mgr = shadow::SyscallManager::instance();
        mgr.set_information_thread(GetCurrentThread(), 0x11, nullptr, 0);  // ThreadHideFromDebugger
#else
        payload->is_debugged = 0;
        payload->is_vm = 0;
        payload->is_suspended = 0;
#endif

        pkt.set_payload(*payload);
        send_packet(pkt, false);
    }

    void handle_game_list(const proto::payload_game_list_t& payload) {
        // Auto-select first game for demo
        if (payload.count > 0) {
            proto::packet_t pkt{proto::packet_type_t::game_select};
            auto* select = pkt.payload_as<proto::payload_game_select_t>();
            select->game_id = 0;
            pkt.set_payload(*select);
            send_packet(pkt, true);
        }
    }

    void handle_pe_chunk(const proto::payload_pe_chunk_t& payload) {
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
        proto::packet_t pkt{proto::packet_type_t::function_request};
        auto* payload = pkt.payload_as<proto::payload_function_request_t>();
        payload->marker_hash = marker_hash;
        payload->timestamp = static_cast<uint32_t>(std::time(nullptr));
        pkt.set_payload(*payload);

        return send_packet(pkt, true).has_value();
    }

    void handle_function_response(const proto::payload_function_response_t& payload) {
        auto& storage = bytecode_storage_t::instance();

        // Extract function name (null-terminated)
        std::string_view function_name(payload.function_name.data());

        // Verify checksum BEFORE storing
        std::span<const uint8_t> code{payload.code.data(), payload.code_size};
        uint32_t received_checksum = payload.checksum;
        uint32_t computed_checksum = simple_checksum(code);

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
        pending_requests_t::instance().complete(payload.marker_hash);
    }

#ifdef _WIN32
    void inject_pe() {
        /*
           use protected function system for PE injection
        */
        std::string target{ target_process_.empty() ? "notepad.exe" : target_process_ };
        uint64_t base_address{ 0 };

        bool success{ CALL_PROTECTED(bool, inject_pe,
            pe_buffer_.data(),
            pe_buffer_.size(),
            pe_entry_rva_,
            target.c_str(),
            target.size(),
            &base_address
        ) };

        /*
           send completion packet
        */
        proto::packet_t pkt{ proto::packet_type_t::pe_complete };
        auto* complete{ pkt.payload_as<proto::payload_pe_complete_t>() };
        complete->success = success ? 1 : 0;
        complete->base_address = base_address;
        pkt.set_payload( *complete );
        send_packet( pkt, true );
    }
#endif
};

} // namespace client

auto main( ) -> int
{
	if ( auto result{ net::network_manager_t::instance( ).init( ) }; !result )
	{
		return 1;
	}

	client::game_client_t client{ };

	/*
	   set up protected function system
	*/
	client::protected_function_caller_t::set_requester( &client );

	if ( auto result{ client.connect( ) }; !result )
	{
		return 1;
	}

	client.run( );

    return 0;
}
