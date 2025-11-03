#include "network.hpp"
#include <cstring>

#ifdef _WIN32
#pragma comment( lib, "ws2_32.lib" )
#else
#include <fcntl.h>
#endif

namespace net
{
	/*
	   socket_wrapper_t implementation
	*/

	/**
	 * @brief close socket
	 */
	auto socket_wrapper_t::close( ) noexcept -> void
	{
		if ( m_fd != INVALID_SOCKET_VALUE )
		{
#ifdef _WIN32
			closesocket( m_fd );
#else
			::close( m_fd );
#endif
			m_fd = INVALID_SOCKET_VALUE;
		}
	}

	/**
	 * @brief set socket to non-blocking mode
	 * @return void or error
	 */
	auto socket_wrapper_t::set_nonblocking( ) noexcept -> std::expected<void, error_t>
	{
#ifdef _WIN32
		u_long mode{ 1 };
		if ( ioctlsocket( m_fd, FIONBIO, &mode ) != 0 )
		{
			return std::unexpected( error_t::invalid_socket );
		}
#else
		int flags{ fcntl( m_fd, F_GETFL, 0 ) };
		if ( flags == -1 ) return std::unexpected( error_t::invalid_socket );
		if ( fcntl( m_fd, F_SETFL, flags | O_NONBLOCK ) == -1 )
		{
			return std::unexpected( error_t::invalid_socket );
		}
#endif
		return { };
	}

	/**
	 * @brief send data through socket
	 * @param data data to send
	 * @return number of bytes sent or error
	 */
	auto socket_wrapper_t::send( std::span<const uint8_t> data ) noexcept -> std::expected<size_t, error_t>
	{
		if ( !valid( ) ) return std::unexpected( error_t::invalid_socket );

#ifdef _WIN32
		int result{ ::send( m_fd, reinterpret_cast<const char*>( data.data( ) ),
		                   static_cast<int>( data.size( ) ), 0 ) };
#else
		ssize_t result{ ::send( m_fd, data.data( ), data.size( ), MSG_NOSIGNAL ) };
#endif

		if ( result < 0 )
		{
			return would_block( ) ? std::expected<size_t, error_t>( 0 )
			                      : std::unexpected( error_t::send_failed );
		}

		return static_cast<size_t>( result );
	}

	/**
	 * @brief receive data from socket
	 * @param buffer buffer to receive into
	 * @return number of bytes received or error
	 */
	auto socket_wrapper_t::recv( std::span<uint8_t> buffer ) noexcept -> std::expected<size_t, error_t>
	{
		if ( !valid( ) ) return std::unexpected( error_t::invalid_socket );

#ifdef _WIN32
		int result{ ::recv( m_fd, reinterpret_cast<char*>( buffer.data( ) ),
		                   static_cast<int>( buffer.size( ) ), 0 ) };
#else
		ssize_t result{ ::recv( m_fd, buffer.data( ), buffer.size( ), 0 ) };
#endif

		if ( result < 0 )
		{
			return would_block( ) ? std::expected<size_t, error_t>( 0 )
			                      : std::unexpected( error_t::recv_failed );
		}

		if ( result == 0 )
		{
			return std::unexpected( error_t::recv_failed );  // Connection closed
		}

		return static_cast<size_t>( result );
	}

	/*
	   network_manager_t implementation
	*/

	/**
	 * @brief destructor
	 */
	network_manager_t::~network_manager_t( )
	{
		cleanup( );
	}

	/**
	 * @brief initialize network subsystem
	 * @return void or error
	 */
	auto network_manager_t::init( ) noexcept -> std::expected<void, error_t>
	{
		if ( m_initialized ) return { };

#ifdef _WIN32
		WSADATA wsa_data{ };
		if ( WSAStartup( MAKEWORD( 2, 2 ), &wsa_data ) != 0 )
		{
			return std::unexpected( error_t::init_failed );
		}
#endif

		m_initialized = true;
		return { };
	}

	/**
	 * @brief cleanup network subsystem
	 */
	auto network_manager_t::cleanup( ) noexcept -> void
	{
		if ( !m_initialized ) return;

#ifdef _WIN32
		WSACleanup( );
#endif

		m_initialized = false;
	}

	/*
	   free functions
	*/

	/**
	 * @brief create a new socket
	 * @return socket or error
	 */
	auto create_socket( ) noexcept -> std::expected<socket_wrapper_t, error_t>
	{
		socket_t fd{ socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) };
		if ( fd == INVALID_SOCKET_VALUE )
		{
			return std::unexpected( error_t::create_failed );
		}

		return socket_wrapper_t{ fd };
	}

	/**
	 * @brief connect to remote host
	 * @param ip IP address
	 * @param port port number
	 * @return connected socket or error
	 */
	auto connect( std::string_view ip, uint16_t port ) noexcept -> std::expected<socket_wrapper_t, error_t>
	{
		auto socket_result{ create_socket( ) };
		if ( !socket_result ) return std::unexpected( socket_result.error( ) );

		sockaddr_in addr{ };
		addr.sin_family = AF_INET;
		addr.sin_port = htons( port );

#ifdef _WIN32
		addr.sin_addr.S_un.S_addr = inet_addr( ip.data( ) );
#else
		if ( inet_pton( AF_INET, ip.data( ), &addr.sin_addr ) <= 0 )
		{
			return std::unexpected( error_t::connect_failed );
		}
#endif

		if ( ::connect( socket_result->get( ), reinterpret_cast<sockaddr*>( &addr ),
		               sizeof( addr ) ) != 0 )
		{
			return std::unexpected( error_t::connect_failed );
		}

		return std::move( *socket_result );
	}

	/**
	 * @brief bind socket to port
	 * @param fd socket file descriptor
	 * @param port port number
	 * @return void or error
	 */
	auto bind( socket_t fd, uint16_t port ) noexcept -> std::expected<void, error_t>
	{
		sockaddr_in addr{ };
		addr.sin_family = AF_INET;
		addr.sin_port = htons( port );
		addr.sin_addr.s_addr = INADDR_ANY;

		if ( ::bind( fd, reinterpret_cast<sockaddr*>( &addr ), sizeof( addr ) ) != 0 )
		{
			return std::unexpected( error_t::bind_failed );
		}

		return { };
	}

	/**
	 * @brief listen for connections
	 * @param fd socket file descriptor
	 * @param backlog connection queue size
	 * @return void or error
	 */
	auto listen( socket_t fd, int backlog ) noexcept -> std::expected<void, error_t>
	{
		if ( ::listen( fd, backlog ) != 0 )
		{
			return std::unexpected( error_t::listen_failed );
		}

		return { };
	}

	/**
	 * @brief accept incoming connection
	 * @param fd socket file descriptor
	 * @param ip client IP address (output)
	 * @param port client port (output)
	 * @return client socket or error
	 */
	auto accept( socket_t fd, std::array<char, 46>& ip, uint16_t& port ) noexcept
		-> std::expected<socket_wrapper_t, error_t>
	{
		sockaddr_in addr{ };
		socklen_t addr_len{ sizeof( addr ) };

		socket_t client_fd{ ::accept( fd, reinterpret_cast<sockaddr*>( &addr ), &addr_len ) };
		if ( client_fd == INVALID_SOCKET_VALUE )
		{
			return would_block( ) ? std::unexpected( error_t::would_block )
			                      : std::unexpected( error_t::invalid_socket );
		}

#ifdef _WIN32
		const char* ip_str{ inet_ntoa( addr.sin_addr ) };
		if ( ip_str )
		{
			std::strncpy( ip.data( ), ip_str, ip.size( ) - 1 );
		}
#else
		inet_ntop( AF_INET, &addr.sin_addr, ip.data( ), ip.size( ) );
#endif

		port = ntohs( addr.sin_port );

		return socket_wrapper_t{ client_fd };
	}

} // namespace net
