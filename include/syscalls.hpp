#pragma once

#ifdef _WIN32

#include <windows.h>
#include <array>
#include <concepts>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <unordered_map>
#include <memory>
#include <format>

namespace shadow
{
	// TODO: Add more NT syscalls for complete functionality:
	//  - NtQueryVirtualMemory (query memory regions)
	//  - NtFreeVirtualMemory (free allocated memory)
	//  - NtReadVirtualMemory (read process memory)
	//  - NtQuerySystemInformation (system info enumeration)
	//  - NtQueryInformationProcess (process information)
	//  - NtSetInformationThread (thread manipulation)
	//  - NtDuplicateObject (handle duplication)
	//
	// TODO: Add syscall number refresh mechanism:
	//  - Detect Windows version changes
	//  - Refresh SSN cache on ntdll.dll reload
	//  - Handle syscall number changes across updates
	//
	// TODO: Add anti-tampering protection:
	//  - Verify ntdll.dll integrity before SSN extraction
	//  - Detect inline hooks in syscall stubs
	//  - Implement syscall instruction unhooking

	/*
	   concepts
	*/

	/**
	 * @brief concept for NT handle types
	 * @tparam T type to check
	 */
	template<typename T>
	concept nt_handle = std::same_as<T, HANDLE> || std::same_as<T, void*>;

	/**
	 * @brief concept for NT status types
	 * @tparam T type to check
	 */
	template<typename T>
	concept nt_status = std::same_as<T, long>;

	/*
	   NT structures
	*/

	/**
	 * @brief unique process identifier
	 */
	struct unique_process_t
	{
		HANDLE value{ };
	};

	/**
	 * @brief unique thread identifier
	 */
	struct unique_thread_t
	{
		HANDLE value{ };
	};

	/**
	 * @brief client identifier
	 */
	struct client_id_t
	{
		unique_process_t process{ };
		unique_thread_t thread{ };
	};

	/**
	 * @brief object attributes
	 */
	struct object_attributes_t
	{
		ULONG length{ sizeof( object_attributes_t ) };
		HANDLE root_directory{ nullptr };
		void* object_name{ nullptr };
		ULONG attributes{ 0 };
		void* security_descriptor{ nullptr };
		void* security_qos{ nullptr };
	};

	/**
	 * @brief RAII wrapper for NT handles
	 */
	class nt_handle_guard_t
	{
		HANDLE m_handle{ nullptr };

	public:
		/**
		 * @brief constructor
		 * @param h handle to wrap
		 */
		explicit nt_handle_guard_t( HANDLE h = nullptr ) : m_handle{ h }
		{
		}

		/**
		 * @brief destructor
		 */
		~nt_handle_guard_t( );

		nt_handle_guard_t( const nt_handle_guard_t& ) = delete;
		auto operator=( const nt_handle_guard_t& ) -> nt_handle_guard_t& = delete;

		/**
		 * @brief move constructor
		 * @param other handle to move from
		 */
		nt_handle_guard_t( nt_handle_guard_t&& other ) noexcept : m_handle{ other.m_handle }
		{
			other.m_handle = nullptr;
		}

		/**
		 * @brief move assignment operator
		 * @param other handle to move from
		 * @return reference to this
		 */
		auto operator=( nt_handle_guard_t&& other ) noexcept -> nt_handle_guard_t&
		{
			if ( this != &other )
			{
				reset( );
				m_handle = other.m_handle;
				other.m_handle = nullptr;
			}
			return *this;
		}

		/**
		 * @brief get handle value
		 * @return handle
		 */
		[[nodiscard]] auto get( ) const noexcept -> HANDLE
		{
			return m_handle;
		}

		/**
		 * @brief release handle ownership
		 * @return handle value
		 */
		[[nodiscard]] auto release( ) noexcept -> HANDLE
		{
			auto h{ m_handle };
			m_handle = nullptr;
			return h;
		}

		/**
		 * @brief reset handle
		 * @param h new handle value
		 */
		auto reset( HANDLE h = nullptr ) -> void;

		/**
		 * @brief boolean conversion
		 * @return true if handle is valid
		 */
		[[nodiscard]] explicit operator bool( ) const noexcept
		{
			return m_handle != nullptr;
		}
	};

	/**
	 * @brief syscall shellcode stub with RAII
	 */
	class syscall_stub_t
	{
		static constexpr std::array<uint8_t, 13> k_template{
			0x49, 0x89, 0xCA,                          // mov r10, rcx
			0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, SSN
			0x0F, 0x05,                                // syscall
			0xC3                                       // ret
		};

		void* m_exec_memory{ nullptr };
		uint32_t m_ssn{ 0 };

	public:
		/**
		 * @brief constructor
		 * @param function_name NT function name
		 */
		explicit syscall_stub_t( std::string_view function_name );

		/**
		 * @brief destructor
		 */
		~syscall_stub_t( );

		syscall_stub_t( const syscall_stub_t& ) = delete;
		auto operator=( const syscall_stub_t& ) -> syscall_stub_t& = delete;

		/**
		 * @brief move constructor
		 * @param other stub to move from
		 */
		syscall_stub_t( syscall_stub_t&& other ) noexcept
			: m_exec_memory{ other.m_exec_memory }, m_ssn{ other.m_ssn }
		{
			other.m_exec_memory = nullptr;
		}

		/**
		 * @brief invoke syscall with arguments
		 * @tparam Ret return type
		 * @tparam Args argument types
		 * @param args syscall arguments
		 * @return syscall result
		 */
		template<typename Ret, typename... Args>
		auto invoke( Args&&... args ) const noexcept -> Ret
		{
			using fn_ptr = Ret( __stdcall* )( Args... );
			return reinterpret_cast<fn_ptr>( m_exec_memory )( std::forward<Args>( args )... );
		}

		/**
		 * @brief check if stub is valid
		 * @return true if executable memory allocated
		 */
		[[nodiscard]] auto valid( ) const noexcept -> bool
		{
			return m_exec_memory != nullptr;
		}

		/**
		 * @brief get syscall number
		 * @return SSN
		 */
		[[nodiscard]] auto ssn( ) const noexcept -> uint32_t
		{
			return m_ssn;
		}
	};

	/**
	 * @brief SSN cache singleton
	 */
	class ssn_cache_t
	{
		std::unordered_map<std::string_view, uint32_t> m_cache{ };
		uint32_t m_windows_build{ 0 };
		void* m_ntdll_base{ nullptr };

		/**
		 * @brief private constructor
		 */
		ssn_cache_t( ) = default;

	public:
		/**
		 * @brief get singleton instance
		 * @return reference to cache
		 */
		static auto instance( ) -> ssn_cache_t&
		{
			static ssn_cache_t cache{ };
			return cache;
		}

		/**
		 * @brief lookup SSN by function name
		 * @param name function name
		 * @return SSN or error
		 */
		auto lookup( std::string_view name ) -> std::expected<uint32_t, std::string_view>;

		/**
		 * @brief insert SSN into cache
		 * @param name function name
		 * @param ssn syscall number
		 */
		auto insert( std::string_view name, uint32_t ssn ) -> void
		{
			m_cache[name] = ssn;
		}

		/**
		 * @brief refresh cache if needed
		 */
		auto refresh_if_needed( ) -> void;

		/**
		 * @brief clear cache
		 */
		auto clear( ) -> void
		{
			m_cache.clear( );
		}

		/**
		 * @brief verify ntdll.dll integrity
		 * @return true if integrity check passed
		 */
		[[nodiscard]] auto verify_ntdll_integrity( ) const noexcept -> bool;
	};

	/**
	 * @brief syscall manager singleton
	 */
	class syscall_manager_t
	{
		std::unique_ptr<syscall_stub_t> m_alloc_vm{ };
		std::unique_ptr<syscall_stub_t> m_write_vm{ };
		std::unique_ptr<syscall_stub_t> m_protect_vm{ };
		std::unique_ptr<syscall_stub_t> m_create_thread{ };
		std::unique_ptr<syscall_stub_t> m_open_process{ };
		std::unique_ptr<syscall_stub_t> m_close{ };

		/*
		   additional syscalls
		*/
		std::unique_ptr<syscall_stub_t> m_query_vm{ };
		std::unique_ptr<syscall_stub_t> m_free_vm{ };
		std::unique_ptr<syscall_stub_t> m_read_vm{ };
		std::unique_ptr<syscall_stub_t> m_query_sys_info{ };
		std::unique_ptr<syscall_stub_t> m_query_proc_info{ };
		std::unique_ptr<syscall_stub_t> m_set_thread_info{ };

		/**
		 * @brief private constructor
		 */
		syscall_manager_t( );

	public:
		/**
		 * @brief get singleton instance
		 * @return reference to manager
		 */
		static auto instance( ) -> syscall_manager_t&
		{
			static syscall_manager_t mgr{ };
			return mgr;
		}

		/**
		 * @brief allocate virtual memory
		 * @param process process handle
		 * @param base base address
		 * @param size allocation size
		 * @param alloc_type allocation type flags
		 * @param protect memory protection flags
		 * @return allocated address or error
		 */
		auto allocate_memory(
			HANDLE process,
			void* base,
			size_t size,
			uint32_t alloc_type,
			uint32_t protect
		) const noexcept -> std::expected<void*, long>;

		/**
		 * @brief write to virtual memory
		 * @param process process handle
		 * @param base base address
		 * @param data data to write
		 * @return bytes written or error
		 */
		auto write_memory(
			HANDLE process,
			void* base,
			std::span<const uint8_t> data
		) const noexcept -> std::expected<size_t, long>;

		/**
		 * @brief change memory protection
		 * @param process process handle
		 * @param base base address
		 * @param size region size
		 * @param new_protect new protection flags
		 * @return old protection flags or error
		 */
		auto protect_memory(
			HANDLE process,
			void* base,
			size_t size,
			uint32_t new_protect
		) const noexcept -> std::expected<uint32_t, long>;

		/**
		 * @brief create remote thread
		 * @param process process handle
		 * @param start_routine thread start address
		 * @param parameter thread parameter
		 * @return thread handle or error
		 */
		auto create_thread(
			HANDLE process,
			void* start_routine,
			void* parameter
		) const noexcept -> std::expected<nt_handle_guard_t, long>;

		/**
		 * @brief open process handle
		 * @param pid process ID
		 * @param access desired access rights
		 * @return process handle or error
		 */
		auto open_process(
			uint32_t pid,
			uint32_t access = PROCESS_ALL_ACCESS
		) const noexcept -> std::expected<nt_handle_guard_t, long>;

		/**
		 * @brief read from virtual memory
		 * @param process process handle
		 * @param base base address
		 * @param buffer output buffer
		 * @return bytes read or error
		 */
		auto read_memory(
			HANDLE process,
			void* base,
			std::span<uint8_t> buffer
		) const noexcept -> std::expected<size_t, long>;

		/**
		 * @brief free virtual memory
		 * @param process process handle
		 * @param base base address
		 * @param size region size
		 * @return void or error
		 */
		auto free_memory(
			HANDLE process,
			void* base,
			size_t size
		) const noexcept -> std::expected<void, long>;

		/**
		 * @brief query virtual memory information
		 * @param process process handle
		 * @param base base address
		 * @param info_class information class
		 * @param info_buffer output buffer
		 * @param info_length buffer length
		 * @param return_length bytes returned
		 * @return void or error
		 */
		auto query_virtual_memory(
			HANDLE process,
			void* base,
			int info_class,
			void* info_buffer,
			size_t info_length,
			size_t* return_length
		) const noexcept -> std::expected<void, long>;

		/**
		 * @brief query process information
		 * @param process process handle
		 * @param info_class information class
		 * @param info_buffer output buffer
		 * @param info_length buffer length
		 * @param return_length bytes returned
		 * @return void or error
		 */
		auto query_information_process(
			HANDLE process,
			int info_class,
			void* info_buffer,
			size_t info_length,
			size_t* return_length
		) const noexcept -> std::expected<void, long>;

		/**
		 * @brief set thread information
		 * @param thread thread handle
		 * @param info_class information class
		 * @param info_buffer input buffer
		 * @param info_length buffer length
		 * @return void or error
		 */
		auto set_information_thread(
			HANDLE thread,
			int info_class,
			void* info_buffer,
			size_t info_length
		) const noexcept -> std::expected<void, long>;
	};

	/**
	 * @brief extract SSN from function address
	 * @param function_address function address in ntdll
	 * @return SSN or error
	 */
	auto extract_ssn( void* function_address ) noexcept -> std::expected<uint32_t, std::string_view>;

} // namespace shadow

#endif // _WIN32
