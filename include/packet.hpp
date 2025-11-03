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

namespace proto
{
	/*
	   compile-time constants
	*/
	inline constexpr uint16_t MAX_PACKET_SIZE{ 2048 };
	inline constexpr uint16_t MAX_PAYLOAD_SIZE{ MAX_PACKET_SIZE - 16 };
	inline constexpr uint32_t PACKET_MAGIC{ 0xDEADBEEF };
	inline constexpr uint16_t PROTOCOL_VERSION{ 1 };
	inline constexpr uint8_t SESSION_KEY_SIZE{ 32 };

	/*
	   packet types enumeration
	*/
	enum class packet_type_t : uint8_t
	{
		connect = 0,
		disconnect,
		challenge,
		challenge_response,
		session_key,
		ack,
		error,
		game_list,
		game_select,
		pe_chunk,
		pe_complete,
		function_request,
		function_response
	};

	/*
	   packet flags enumeration
	*/
	enum class packet_flags_t : uint8_t
	{
		none = 0,
		encrypted = 1 << 0,
		compressed = 1 << 1
	};

	/**
	 * @brief bitwise OR operator for packet flags
	 * @param a first flag
	 * @param b second flag
	 * @return combined flags
	 */
	constexpr auto operator|( packet_flags_t a, packet_flags_t b ) noexcept -> packet_flags_t
	{
		return static_cast<packet_flags_t>( std::to_underlying( a ) | std::to_underlying( b ) );
	}

	/**
	 * @brief bitwise AND operator for packet flags
	 * @param a first flag
	 * @param b second flag
	 * @return intersection of flags
	 */
	constexpr auto operator&( packet_flags_t a, packet_flags_t b ) noexcept -> packet_flags_t
	{
		return static_cast<packet_flags_t>( std::to_underlying( a ) & std::to_underlying( b ) );
	}

	/**
	 * @brief check if flags contain a specific flag
	 * @param flags flags to check
	 * @param flag flag to look for
	 * @return true if flag is present
	 */
	constexpr auto has_flag( packet_flags_t flags, packet_flags_t flag ) noexcept -> bool
	{
		return ( flags & flag ) == flag;
	}

	/**
	 * @brief packet header structure (fixed size, optimized layout)
	 */
	struct alignas( 8 ) packet_header_t
	{
		uint32_t magic{ PACKET_MAGIC };
		uint16_t version{ PROTOCOL_VERSION };
		uint16_t length{ 0 };
		packet_type_t type{ packet_type_t::connect };
		packet_flags_t flags{ packet_flags_t::none };
		uint16_t sequence{ 0 };
		uint32_t crc32{ 0 };

		/**
		 * @brief validate header magic and version
		 * @return true if header is valid
		 */
		[[nodiscard]] constexpr auto valid( ) const noexcept -> bool
		{
			return magic == PACKET_MAGIC && version == PROTOCOL_VERSION;
		}
	};

	static_assert( sizeof( packet_header_t ) == 16, "Header must be 16 bytes" );

	/**
	 * @brief network packet structure
	 */
	struct packet_t
	{
		packet_header_t header{ };
		std::array<uint8_t, MAX_PAYLOAD_SIZE> payload{ };

		/**
		 * @brief default constructor
		 */
		constexpr packet_t( ) noexcept = default;

		/**
		 * @brief construct packet with type
		 * @param type packet type
		 */
		explicit constexpr packet_t( packet_type_t type ) noexcept
		{
			header.type = type;
		}

		/**
		 * @brief get packet type
		 * @return packet type
		 */
		[[nodiscard]] constexpr auto type( ) const noexcept -> packet_type_t
		{
			return header.type;
		}

		/**
		 * @brief get payload length
		 * @return payload length in bytes
		 */
		[[nodiscard]] constexpr auto length( ) const noexcept -> uint16_t
		{
			return header.length;
		}

		/**
		 * @brief check if packet has specific flag
		 * @param flag flag to check
		 * @return true if flag is set
		 */
		[[nodiscard]] constexpr auto has_flag( packet_flags_t flag ) const noexcept -> bool
		{
			return proto::has_flag( header.flags, flag );
		}

		/**
		 * @brief set packet flag
		 * @param flag flag to set
		 */
		constexpr auto set_flag( packet_flags_t flag ) noexcept -> void
		{
			header.flags = header.flags | flag;
		}

		/**
		 * @brief clear packet flag
		 * @param flag flag to clear
		 */
		constexpr auto clear_flag( packet_flags_t flag ) noexcept -> void
		{
			header.flags = static_cast<packet_flags_t>(
				std::to_underlying( header.flags ) & ~std::to_underlying( flag )
			);
		}

		/**
		 * @brief get mutable payload view
		 * @return span of payload data
		 */
		[[nodiscard]] constexpr auto payload_view( ) noexcept -> std::span<uint8_t>
		{
			return { payload.data( ), header.length };
		}

		/**
		 * @brief get const payload view
		 * @return const span of payload data
		 */
		[[nodiscard]] constexpr auto payload_view( ) const noexcept -> std::span<const uint8_t>
		{
			return { payload.data( ), header.length };
		}

		/**
		 * @brief get typed pointer to payload
		 * @tparam T type to cast payload to
		 * @return pointer to payload as type T
		 */
		template<typename T>
		[[nodiscard]] constexpr auto payload_as( ) noexcept -> T*
		{
			static_assert( sizeof( T ) <= MAX_PAYLOAD_SIZE );
			return std::bit_cast<T*>( payload.data( ) );
		}

		/**
		 * @brief get const typed pointer to payload
		 * @tparam T type to cast payload to
		 * @return const pointer to payload as type T
		 */
		template<typename T>
		[[nodiscard]] constexpr auto payload_as( ) const noexcept -> const T*
		{
			static_assert( sizeof( T ) <= MAX_PAYLOAD_SIZE );
			return std::bit_cast<const T*>( payload.data( ) );
		}

		/**
		 * @brief set payload from typed data
		 * @tparam T type of data
		 * @param data data to set as payload
		 */
		template<typename T>
		constexpr auto set_payload( const T& data ) noexcept -> void
		{
			static_assert( std::is_trivially_copyable_v<T> );
			static_assert( sizeof( T ) <= MAX_PAYLOAD_SIZE );
			std::memcpy( payload.data( ), &data, sizeof( T ) );
			header.length = sizeof( T );
		}

		/**
		 * @brief serialize packet to buffer
		 * @param buffer destination buffer
		 * @return number of bytes written, 0 on failure
		 */
		[[nodiscard]] auto serialize( std::span<uint8_t> buffer ) const noexcept -> uint16_t;

		/**
		 * @brief deserialize packet from buffer
		 * @param buffer source buffer
		 * @return packet or error message
		 */
		[[nodiscard]] static auto deserialize( std::span<const uint8_t> buffer ) noexcept
			-> std::expected<packet_t, std::string_view>;
	};

	/*
	   payload structures (POD for network transmission)
	*/

	/**
	 * @brief challenge payload structure
	 */
	struct payload_challenge_t
	{
		uint32_t challenge{ };
		uint32_t timestamp{ };
	};

	/**
	 * @brief challenge response payload structure
	 */
	struct payload_challenge_response_t
	{
		uint32_t challenge_solution{ };
		uint8_t is_debugged{ };
		uint8_t is_vm{ };
		uint8_t is_suspended{ };
		uint8_t reserved{ };
	};

	/**
	 * @brief session key payload structure
	 */
	struct payload_session_key_t
	{
		std::array<uint8_t, SESSION_KEY_SIZE> key{ };
	};

	/**
	 * @brief game list payload structure
	 */
	struct payload_game_list_t
	{
		uint32_t count{ };
		std::array<std::array<char, 64>, 16> games{ };
	};

	/**
	 * @brief game selection payload structure
	 */
	struct payload_game_select_t
	{
		uint32_t game_id{ };
	};

	/**
	 * @brief PE chunk payload structure
	 */
	struct payload_pe_chunk_t
	{
		uint32_t chunk_index{ };
		uint32_t total_chunks{ };
		uint32_t chunk_size{ };
		uint32_t total_size{ };
		uint32_t entry_rva{ };
		std::array<uint8_t, MAX_PAYLOAD_SIZE - 20> data{ };
	};

	/**
	 * @brief PE complete payload structure
	 */
	struct payload_pe_complete_t
	{
		uint8_t success{ };
		uint8_t reserved[3]{ };
		uint32_t thread_id{ };
		uint64_t base_address{ };
	};

	/**
	 * @brief function request payload structure
	 */
	struct payload_function_request_t
	{
		uint32_t marker_hash{ };
		uint32_t timestamp{ };
	};

	/**
	 * @brief function response payload structure
	 */
	struct payload_function_response_t
	{
		uint32_t marker_hash{ };
		uint32_t code_size{ };
		std::array<char, 64> function_name{ };
		uint32_t checksum{ };
		std::array<uint8_t, MAX_PAYLOAD_SIZE - 76> code{ };
	};

	/**
	 * @brief check if data should be compressed
	 * @param data data to check
	 * @return true if compression is recommended
	 */
	[[nodiscard]] constexpr auto should_compress( std::span<const uint8_t> data ) noexcept -> bool
	{
		return data.size( ) > 256;
	}

} // namespace proto
