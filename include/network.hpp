#pragma once

#include <cstdint>
#include <span>
#include <array>
#include <string_view>
#include <concepts>
#include <expected>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t INVALID_SOCKET_VALUE{ INVALID_SOCKET };
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t INVALID_SOCKET_VALUE{ -1 };
#endif

namespace net
{
	/*
	   concepts for type safety
	*/

	/**
	 * @brief concept for socket types
	 * @tparam T type to check
	 */
	template<typename T>
	concept socket_type = std::same_as<T, socket_t>;

	/**
	 * @brief concept for address types
	 * @tparam T type to check
	 */
	template<typename T>
	concept address_type = requires( T addr )
	{
		{ addr.sin_family } -> std::convertible_to<uint16_t>;
		{ addr.sin_port } -> std::convertible_to<uint16_t>;
	};

	/*
	   error enumeration
	*/

	/**
	 * @brief network error codes
	 */
	enum class error_t : int32_t
	{
		none = 0,
		init_failed,
		create_failed,
		bind_failed,
		listen_failed,
		connect_failed,
		send_failed,
		recv_failed,
		invalid_socket,
		would_block
	};

	/**
	 * @brief RAII socket wrapper
	 */
	class socket_wrapper_t
	{
		socket_t m_fd{ INVALID_SOCKET_VALUE };

	public:
		/**
		 * @brief default constructor
		 */
		constexpr socket_wrapper_t( ) noexcept = default;

		/**
		 * @brief construct from socket descriptor
		 * @param fd socket file descriptor
		 */
		explicit socket_wrapper_t( socket_t fd ) noexcept : m_fd{ fd }
		{
		}

		/**
		 * @brief destructor
		 */
		~socket_wrapper_t( ) noexcept
		{
			close( );
		}

		socket_wrapper_t( const socket_wrapper_t& ) = delete;
		auto operator=( const socket_wrapper_t& ) -> socket_wrapper_t& = delete;

		/**
		 * @brief move constructor
		 * @param other socket to move from
		 */
		socket_wrapper_t( socket_wrapper_t&& other ) noexcept : m_fd{ other.m_fd }
		{
			other.m_fd = INVALID_SOCKET_VALUE;
		}

		/**
		 * @brief move assignment operator
		 * @param other socket to move from
		 * @return reference to this socket
		 */
		auto operator=( socket_wrapper_t&& other ) noexcept -> socket_wrapper_t&
		{
			if ( this != &other )
			{
				close( );
				m_fd = other.m_fd;
				other.m_fd = INVALID_SOCKET_VALUE;
			}
			return *this;
		}

		/**
		 * @brief get socket file descriptor
		 * @return socket file descriptor
		 */
		[[nodiscard]] constexpr auto get( ) const noexcept -> socket_t
		{
			return m_fd;
		}

		/**
		 * @brief check if socket is valid
		 * @return true if socket is valid
		 */
		[[nodiscard]] constexpr auto valid( ) const noexcept -> bool
		{
			return m_fd != INVALID_SOCKET_VALUE;
		}

		/**
		 * @brief boolean conversion operator
		 * @return true if socket is valid
		 */
		[[nodiscard]] constexpr explicit operator bool( ) const noexcept
		{
			return valid( );
		}

		/**
		 * @brief close socket
		 */
		auto close( ) noexcept -> void;

		/**
		 * @brief release socket ownership
		 * @return socket file descriptor
		 */
		[[nodiscard]] auto release( ) noexcept -> socket_t
		{
			auto fd{ m_fd };
			m_fd = INVALID_SOCKET_VALUE;
			return fd;
		}

		/**
		 * @brief set socket to non-blocking mode
		 * @return void or error
		 */
		[[nodiscard]] auto set_nonblocking( ) noexcept -> std::expected<void, error_t>;

		/**
		 * @brief send data through socket
		 * @param data data to send
		 * @return number of bytes sent or error
		 */
		[[nodiscard]] auto send( std::span<const uint8_t> data ) noexcept -> std::expected<size_t, error_t>;

		/**
		 * @brief receive data from socket
		 * @param buffer buffer to receive into
		 * @return number of bytes received or error
		 */
		[[nodiscard]] auto recv( std::span<uint8_t> buffer ) noexcept -> std::expected<size_t, error_t>;
	};

	/**
	 * @brief network manager (singleton)
	 */
	class network_manager_t
	{
		bool m_initialized{ false };

		/**
		 * @brief private constructor
		 */
		network_manager_t( ) = default;

		/**
		 * @brief destructor
		 */
		~network_manager_t( );

	public:
		/**
		 * @brief get singleton instance
		 * @return reference to network manager
		 */
		static auto instance( ) -> network_manager_t&
		{
			static network_manager_t mgr{ };
			return mgr;
		}

		network_manager_t( const network_manager_t& ) = delete;
		auto operator=( const network_manager_t& ) -> network_manager_t& = delete;

		/**
		 * @brief initialize network subsystem
		 * @return void or error
		 */
		[[nodiscard]] auto init( ) noexcept -> std::expected<void, error_t>;

		/**
		 * @brief cleanup network subsystem
		 */
		auto cleanup( ) noexcept -> void;
	};

	/*
	   free functions for network operations
	*/

	/**
	 * @brief create a new socket
	 * @return socket or error
	 */
	[[nodiscard]] auto create_socket( ) noexcept -> std::expected<socket_wrapper_t, error_t>;

	/**
	 * @brief connect to remote host
	 * @param ip IP address
	 * @param port port number
	 * @return connected socket or error
	 */
	[[nodiscard]] auto connect( std::string_view ip, uint16_t port ) noexcept
		-> std::expected<socket_wrapper_t, error_t>;

	/**
	 * @brief bind socket to port
	 * @param fd socket file descriptor
	 * @param port port number
	 * @return void or error
	 */
	[[nodiscard]] auto bind( socket_t fd, uint16_t port ) noexcept -> std::expected<void, error_t>;

	/**
	 * @brief listen for connections
	 * @param fd socket file descriptor
	 * @param backlog connection queue size
	 * @return void or error
	 */
	[[nodiscard]] auto listen( socket_t fd, int backlog ) noexcept -> std::expected<void, error_t>;

	/**
	 * @brief accept incoming connection
	 * @param fd socket file descriptor
	 * @param ip client IP address (output)
	 * @param port client port (output)
	 * @return client socket or error
	 */
	[[nodiscard]] auto accept( socket_t fd, std::array<char, 46>& ip, uint16_t& port ) noexcept
		-> std::expected<socket_wrapper_t, error_t>;

	/**
	 * @brief check if last error was would-block
	 * @return true if operation would block
	 */
	[[nodiscard]] constexpr auto would_block( ) noexcept -> bool
	{
#ifdef _WIN32
		return WSAGetLastError( ) == WSAEWOULDBLOCK;
#else
		return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
	}

} // namespace net
