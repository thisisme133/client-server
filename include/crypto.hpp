#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <concepts>

namespace crypto
{
	/*
	   concepts for type safety
	*/

	/**
	 * @brief concept for key types
	 * @tparam T type to check
	 */
	template<typename T>
	concept key_type = requires( T key )
	{
		{ key.data( ) } -> std::convertible_to<const uint8_t*>;
		{ key.size( ) } -> std::convertible_to<size_t>;
	};

	/**
	 * @brief compile-time XOR cipher (fast, inline)
	 * @tparam K key type
	 * @param data data to encrypt/decrypt
	 * @param key encryption key
	 */
	template<key_type K>
	constexpr auto xor_cipher( std::span<uint8_t> data, const K& key ) noexcept -> void
	{
		const auto key_span{ std::span{ key.data( ), key.size( ) } };

		for ( size_t i{ 0 }; i < data.size( ); ++i )
		{
			data[i] ^= key_span[i % key_span.size( )];
		}
	}

	/**
	 * @brief inline encryption (XOR-based)
	 * @tparam K key type
	 * @param key encryption key
	 * @param input input data
	 * @param output output buffer
	 */
	template<key_type K>
	inline auto encrypt( const K& key, std::span<const uint8_t> input, std::span<uint8_t> output ) noexcept -> void
	{
		const auto key_span{ std::span{ key.data( ), key.size( ) } };
		const size_t size{ std::min( input.size( ), output.size( ) ) };

		for ( size_t i{ 0 }; i < size; ++i )
		{
			output[i] = input[i] ^ key_span[i % key_span.size( )];
		}
	}

	/**
	 * @brief inline decryption (XOR-based, symmetric)
	 * @tparam K key type
	 * @param key decryption key
	 * @param input input data
	 * @param output output buffer
	 */
	template<key_type K>
	inline auto decrypt( const K& key, std::span<const uint8_t> input, std::span<uint8_t> output ) noexcept -> void
	{
		encrypt( key, input, output );  // XOR is symmetric
	}

	/**
	 * @brief solve challenge (constexpr for compile-time evaluation)
	 * @param challenge challenge value
	 * @return solution to challenge
	 */
	[[nodiscard]] constexpr auto solve_challenge( uint32_t challenge ) noexcept -> uint32_t
	{
		/*
		   simple hash-based challenge
		*/
		uint32_t result{ challenge };
		result ^= ( result << 13 );
		result ^= ( result >> 17 );
		result ^= ( result << 5 );
		return result * 0x9E3779B9;
	}

	/**
	 * @brief CRC32 lookup table (compile-time generated)
	 */
	inline constexpr auto crc32_table{ []( ) constexpr
	{
		std::array<uint32_t, 256> table{ };
		for ( uint32_t i{ 0 }; i < 256; ++i )
		{
			uint32_t crc{ i };
			for ( uint32_t j{ 0 }; j < 8; ++j )
			{
				crc = ( crc >> 1 ) ^ ( ( crc & 1 ) ? 0xEDB88320 : 0 );
			}
			table[i] = crc;
		}
		return table;
	}( ) };

	/**
	 * @brief fast CRC32 calculator
	 */
	class crc32_t
	{
	public:
		/**
		 * @brief compute CRC32 checksum
		 * @param data data to checksum
		 * @return CRC32 value
		 */
		[[nodiscard]] static constexpr auto compute( std::span<const uint8_t> data ) noexcept -> uint32_t
		{
			uint32_t crc{ 0xFFFFFFFF };
			for ( uint8_t byte : data )
			{
				crc = crc32_table[( crc ^ byte ) & 0xFF] ^ ( crc >> 8 );
			}
			return ~crc;
		}

		/**
		 * @brief compute CRC32 checksum from raw pointer
		 * @param data pointer to data
		 * @param size size of data
		 * @return CRC32 value
		 */
		[[nodiscard]] static constexpr auto compute( const void* data, size_t size ) noexcept -> uint32_t
		{
			return compute( std::span{ static_cast<const uint8_t*>( data ), size } );
		}
	};

} // namespace crypto
