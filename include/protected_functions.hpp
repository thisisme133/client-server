#pragma once

#include <cstdint>
#include <cstring>
#include <string_view>
#include <span>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace protect
{
	/**
	 * @brief compile-time FNV-1a hash for function markers
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
	 * @brief function marker - identifies a protected function
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
		 * @brief equality operator
		 * @param other other marker
		 * @return true if equal
		 */
		constexpr auto operator==( const function_marker_t& other ) const noexcept -> bool
		{
			return hash == other.hash && name == other.name;
		}
	};

	/**
	 * @brief temporary function executor
	 *
	 * Allocates executable memory, executes bytecode, then immediately frees it.
	 * Supports W^X systems by using RW -> RX transition.
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
			   try RWX first (most common on Windows)
			*/
			m_exec_memory = VirtualAlloc( nullptr, m_size,
			                              MEM_COMMIT | MEM_RESERVE,
			                              PAGE_EXECUTE_READWRITE );

			if ( !m_exec_memory )
			{
				/*
				   if RWX fails, try RW -> RX
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
		 * @return true if executable memory allocated
		 */
		[[nodiscard]] auto valid( ) const noexcept -> bool
		{
			return m_exec_memory != nullptr;
		}
	};

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

} // namespace protect

/*
   macros for protected function definition and calling
*/
#define MARKER( name ) ::protect::function_marker_t{ #name }

#ifdef PROTECTED_FUNCTION_SERVER
	/*
	   server side: real implementation
	*/
	#define MARKER_DEF( RetType, Name ) \
		static auto Name
#else
	/*
	   client side: stub that will request from server
	*/
	#define MARKER_DEF( RetType, Name ) \
		static auto Name [[maybe_unused]]

	/*
	   macro for calling protected functions from client code
	   Usage: CALL_PROTECTED(bool, check_debugger_present, arg1, arg2, ...)
	*/
	#define CALL_PROTECTED( RetType, FuncName, ... ) \
		::client::protected_function_caller_t::call<RetType>( MARKER( FuncName ), ##__VA_ARGS__ )
#endif
