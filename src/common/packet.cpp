#include "packet.hpp"
#include "crypto.hpp"
#include <cstring>

namespace proto
{
	/**
	 * @brief serialize packet to buffer
	 * @param buffer destination buffer
	 * @return number of bytes written, 0 on failure
	 */
	auto packet_t::serialize( std::span<uint8_t> buffer ) const noexcept -> uint16_t
	{
		if ( buffer.size( ) < sizeof( packet_header_t ) + header.length )
		{
			return 0;
		}

		/*
		   copy header
		*/
		std::memcpy( buffer.data( ), &header, sizeof( packet_header_t ) );

		/*
		   copy payload
		*/
		if ( header.length > 0 )
		{
			std::memcpy( buffer.data( ) + sizeof( packet_header_t ), payload.data( ), header.length );
		}

		return sizeof( packet_header_t ) + header.length;
	}

	/**
	 * @brief deserialize packet from buffer
	 * @param buffer source buffer
	 * @return packet or error message
	 */
	auto packet_t::deserialize( std::span<const uint8_t> buffer ) noexcept
		-> std::expected<packet_t, std::string_view>
	{
		if ( buffer.size( ) < sizeof( packet_header_t ) )
		{
			return std::unexpected( "Buffer too small for header" );
		}

		packet_t packet{ };
		std::memcpy( &packet.header, buffer.data( ), sizeof( packet_header_t ) );

		if ( !packet.header.valid( ) )
		{
			return std::unexpected( "Invalid packet magic or version" );
		}

		if ( packet.header.length > MAX_PAYLOAD_SIZE )
		{
			return std::unexpected( "Payload too large" );
		}

		if ( buffer.size( ) < sizeof( packet_header_t ) + packet.header.length )
		{
			return std::unexpected( "Buffer too small for payload" );
		}

		/*
		   copy payload
		*/
		if ( packet.header.length > 0 )
		{
			std::memcpy( packet.payload.data( ), buffer.data( ) + sizeof( packet_header_t ),
			           packet.header.length );
		}

		return packet;
	}

} // namespace proto
