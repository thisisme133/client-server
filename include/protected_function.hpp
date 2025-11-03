#pragma once

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string_view>
#include <functional>
#include <unordered_map>
#include <expected>
#include <span>
#include <memory>
#include <mutex>
#include <condition_variable>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace protect
{
	/**
	 * @brief compile-time hash for function markers (FNV-1a)
	 * @param str string to hash
	 * @return hash value
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
	 * @brief marker type - identifies a protected function
	 */
	struct function_marker_t
	{
		uint32_t hash{ };
		std::string_view name{ };

		/**
		 * @brief construct marker from name
		 * @param n function name
		 */
		constexpr function_marker_t( std::string_view n ) noexcept
			: hash{ fnv1a_hash( n ) }, name{ n }
		{
		}

		/**
		 * @brief equality operator (checks both hash AND name to prevent collision attacks)
		 * @param other other marker
		 * @return true if markers are equal
		 */
		constexpr auto operator==( const function_marker_t& other ) const noexcept -> bool
		{
			return hash == other.hash && name == other.name;
		}
	};

	/*
	   macros for protected function definition
	*/
	#define MARKER( name ) ::protect::function_marker_t{ #name }

	#ifdef PROTECTED_FUNCTION_SERVER
		#define MARKER_DEF( RetType, Name ) \
			static auto Name
	#else
		#define MARKER_DEF( RetType, Name ) \
			static auto Name [[maybe_unused]]
	#endif

	/**
	 * @brief temporary function executor
	 *
	 * Allocates executable memory, executes code, then immediately frees it.
	 * Supports W^X systems (SELinux, hardened Linux) by using RW -> RX transition.
	 * This prevents the function from staying in memory for analysis.
	 */
	class temporary_function_t
	{
		void* m_exec_memory{ nullptr };
		size_t m_size{ 0 };
		bool m_using_wx_separate{ false };

	public:
		/**
		 * @brief construct temporary function from bytecode
		 * @param bytecode function bytecode
		 */
		explicit temporary_function_t( std::span<const uint8_t> bytecode ) : m_size{ bytecode.size( ) }
		{
			if ( bytecode.empty( ) ) return;

#ifdef _WIN32
			/*
			   try RWX first (most common)
			*/
			m_exec_memory = VirtualAlloc( nullptr, m_size,
			                              MEM_COMMIT | MEM_RESERVE,
			                              PAGE_EXECUTE_READWRITE );

			if ( !m_exec_memory )
			{
				/*
				   if RWX fails (rare on Windows), try RW -> RX
				*/
				m_exec_memory = VirtualAlloc( nullptr, m_size,
				                              MEM_COMMIT | MEM_RESERVE,
				                              PAGE_READWRITE );
				m_using_wx_separate = true;
			}

			if ( m_exec_memory )
			{
				std::memcpy( m_exec_memory, bytecode.data( ), m_size );

				/*
				   if using W^X, change to RX now
				*/
				if ( m_using_wx_separate )
				{
					DWORD old_protect{ };
					VirtualProtect( m_exec_memory, m_size, PAGE_EXECUTE_READ, &old_protect );
				}
			}
#else
			/*
			   try RWX first
			*/
			m_exec_memory = mmap( nullptr, m_size,
			                      PROT_READ | PROT_WRITE | PROT_EXEC,
			                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );

			if ( m_exec_memory == MAP_FAILED )
			{
				/*
				   W^X enforcement - try RW -> RX
				*/
				m_exec_memory = mmap( nullptr, m_size,
				                      PROT_READ | PROT_WRITE,
				                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
				m_using_wx_separate = true;
			}

			if ( m_exec_memory != MAP_FAILED )
			{
				std::memcpy( m_exec_memory, bytecode.data( ), m_size );

				/*
				   flush instruction cache and change to RX
				*/
				if ( m_using_wx_separate )
				{
					__builtin___clear_cache(
						reinterpret_cast<char*>( m_exec_memory ),
						reinterpret_cast<char*>( m_exec_memory ) + m_size
					);
					mprotect( m_exec_memory, m_size, PROT_READ | PROT_EXEC );
				}
			}
			else
			{
				m_exec_memory = nullptr;
			}
#endif
		}

		/**
		 * @brief destructor - immediately frees executable memory
		 */
		~temporary_function_t( )
		{
			if ( m_exec_memory )
			{
#ifdef _WIN32
				VirtualFree( m_exec_memory, 0, MEM_RELEASE );
#else
				munmap( m_exec_memory, m_size );
#endif
				m_exec_memory = nullptr;
			}
		}

		temporary_function_t( const temporary_function_t& ) = delete;
		auto operator=( const temporary_function_t& ) -> temporary_function_t& = delete;
		temporary_function_t( temporary_function_t&& ) = delete;

		/**
		 * @brief execute function with arguments
		 * @tparam Ret return type
		 * @tparam Args argument types
		 * @param args function arguments
		 * @return function result
		 */
		template<typename Ret, typename... Args>
		auto execute( Args&&... args ) const -> Ret
		{
			if ( !m_exec_memory )
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

			using fn_ptr = Ret( * )( Args... );
			auto fn{ reinterpret_cast<fn_ptr>( m_exec_memory ) };
			return fn( std::forward<Args>( args )... );
		}

		/**
		 * @brief check if function is valid
		 * @return true if executable memory allocated successfully
		 */
		[[nodiscard]] auto valid( ) const noexcept -> bool
		{
			return m_exec_memory != nullptr;
		}
	};

	/**
	 * @brief simple checksum for bytecode integrity verification
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
	 *
	 * Stores raw bytes with integrity verification.
	 * RWX memory is allocated only during execution and freed immediately after.
	 */
	class bytecode_storage_t
	{
		/**
		 * @brief bytecode entry structure
		 */
		struct bytecode_entry_t
		{
			std::string name{ };
			std::vector<uint8_t> code{ };
			uint32_t checksum{ };
			size_t expected_size{ };
		};

		std::unordered_map<uint32_t, bytecode_entry_t> m_storage{ };
		std::mutex m_mutex{ };

		/**
		 * @brief private constructor (singleton)
		 */
		bytecode_storage_t( ) = default;

	public:
		/**
		 * @brief get singleton instance
		 * @return reference to storage
		 */
		static auto instance( ) -> bytecode_storage_t&
		{
			static bytecode_storage_t storage{ };
			return storage;
		}

		/**
		 * @brief store bytecode with name verification and integrity check
		 * @param marker_hash function marker hash
		 * @param name function name
		 * @param code function bytecode
		 * @return true if stored successfully
		 */
		auto store( uint32_t marker_hash, std::string_view name, std::span<const uint8_t> code ) -> bool
		{
			std::lock_guard lock{ m_mutex };

			/*
			   detect hash collision - different name with same hash
			*/
			auto it{ m_storage.find( marker_hash ) };
			if ( it != m_storage.end( ) && it->second.name != name )
			{
				// CRITICAL: Hash collision detected!
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

		/**
		 * @brief get bytecode with integrity verification
		 * @param marker_hash function marker hash
		 * @param expected_name expected function name
		 * @return bytecode or empty vector on error
		 */
		auto get( uint32_t marker_hash, std::string_view expected_name ) -> std::vector<uint8_t>
		{
			std::lock_guard lock{ m_mutex };
			auto it{ m_storage.find( marker_hash ) };

			if ( it == m_storage.end( ) )
			{
				return { };
			}

			auto& entry{ it->second };

			/*
			   verify name matches (collision detection)
			*/
			if ( entry.name != expected_name )
			{
				return { };
			}

			/*
			   verify integrity
			*/
			uint32_t actual_checksum{ simple_checksum( entry.code ) };
			if ( actual_checksum != entry.checksum )
			{
				// Bytecode corrupted!
				m_storage.erase( it );
				return { };
			}

			/*
			   verify size
			*/
			if ( entry.code.size( ) != entry.expected_size )
			{
				// Size mismatch!
				m_storage.erase( it );
				return { };
			}

			return entry.code;
		}

		/**
		 * @brief check if function exists in storage
		 * @param marker_hash function marker hash
		 * @param expected_name expected function name
		 * @return true if function exists and name matches
		 */
		auto has( uint32_t marker_hash, std::string_view expected_name ) -> bool
		{
			std::lock_guard lock{ m_mutex };
			auto it{ m_storage.find( marker_hash ) };
			return it != m_storage.end( ) && it->second.name == expected_name;
		}

		/**
		 * @brief clear all stored functions
		 */
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
		/**
		 * @brief request structure
		 */
		struct request_t
		{
			uint32_t marker_hash{ };
			std::mutex mutex{ };
			std::condition_variable cv{ };
			bool completed{ false };
		};

		std::unordered_map<uint32_t, std::shared_ptr<request_t>> m_requests{ };
		std::mutex m_mutex{ };

		/**
		 * @brief private constructor (singleton)
		 */
		pending_requests_t( ) = default;

	public:
		/**
		 * @brief get singleton instance
		 * @return reference to pending requests
		 */
		static auto instance( ) -> pending_requests_t&
		{
			static pending_requests_t pending{ };
			return pending;
		}

		/**
		 * @brief add pending request
		 * @param marker_hash function marker hash
		 * @return shared pointer to request
		 */
		auto add( uint32_t marker_hash ) -> std::shared_ptr<request_t>
		{
			std::lock_guard lock{ m_mutex };
			auto req{ std::make_shared<request_t>( ) };
			req->marker_hash = marker_hash;
			m_requests[marker_hash] = req;
			return req;
		}

		/**
		 * @brief complete pending request
		 * @param marker_hash function marker hash
		 */
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

		/**
		 * @brief remove pending request (e.g., on immediate send failure)
		 * @param marker_hash function marker hash
		 */
		auto remove( uint32_t marker_hash ) -> void
		{
			std::lock_guard lock{ m_mutex };
			m_requests.erase( marker_hash );
		}

		/**
		 * @brief wait for request completion
		 * @param marker_hash function marker hash
		 * @param timeout timeout duration
		 * @return true if completed within timeout
		 */
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

			/*
			   CRITICAL: Clean up request from map regardless of success/failure
			   This prevents memory leaks and allows retries
			*/
			{
				std::lock_guard map_lock{ m_mutex };
				auto it{ m_requests.find( marker_hash ) };
				if ( it != m_requests.end( ) && !it->second->completed )
				{
					// Only remove if not completed (complete() already removed it)
					m_requests.erase( it );
				}
			}

			return success;
		}
	};

	/*
	   forward declaration
	*/
	class function_requester_t;

	/**
	 * @brief global protected function caller
	 */
	class fn_protect_global_t
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
		 * @return function result or error message
		 */
		template<typename Ret, typename... Args>
		static auto call( function_marker_t marker, Args&&... args ) -> std::expected<Ret, std::string_view>
		{
			auto& storage{ bytecode_storage_t::instance( ) };

			/*
			   check if bytecode is in storage (with name verification)
			*/
			std::vector<uint8_t> bytecode{ storage.get( marker.hash, marker.name ) };

			/*
			   if not in storage, request from server
			*/
			if ( bytecode.empty( ) )
			{
				if ( !m_requester )
				{
					return std::unexpected( "No function requester set" );
				}

				/*
				   request function and wait for response
				*/
				if ( !request_and_wait( marker.hash ) )
				{
					return std::unexpected( "Failed to receive function from server" );
				}

				/*
				   get bytecode from storage with verification
				*/
				bytecode = storage.get( marker.hash, marker.name );
				if ( bytecode.empty( ) )
				{
					return std::unexpected( "Function bytecode not available or integrity check failed" );
				}
			}

			/*
			   additional size sanity check
			*/
			if ( bytecode.size( ) > 1024 * 1024 )  // 1MB max
			{
				return std::unexpected( "Function bytecode too large - possible corruption" );
			}

			if ( bytecode.size( ) < 4 )  // Minimum viable function size
			{
				return std::unexpected( "Function bytecode too small - possible corruption" );
			}

			/*
			   allocate executable memory temporarily (RAII - freed on scope exit)
			   Supports both RWX and W^X systems
			*/
			temporary_function_t temp_fn{ bytecode };

			if ( !temp_fn.valid( ) )
			{
				return std::unexpected( "Failed to allocate executable memory (W^X or SELinux may be blocking)" );
			}

			/*
			   execute function - memory will be freed automatically when temp_fn goes out of scope
			*/
			return temp_fn.execute<Ret>( std::forward<Args>( args )... );
		}

	private:
		/**
		 * @brief request function and wait for response
		 * @param marker_hash function marker hash
		 * @return true if request succeeded
		 */
		static auto request_and_wait( uint32_t marker_hash ) -> bool;
	};

	/**
	 * @brief function requester interface (implemented by client)
	 */
	class function_requester_t
	{
	public:
		/**
		 * @brief virtual destructor
		 */
		virtual ~function_requester_t( ) = default;

		/**
		 * @brief request function from server
		 * @param marker_hash function marker hash
		 * @return true if request sent successfully
		 */
		virtual auto request_function( uint32_t marker_hash ) -> bool = 0;
	};

} // namespace protect
