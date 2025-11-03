#pragma once

#include "protected_functions.hpp"

#ifdef _WIN32
#include "syscalls.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <vector>
#endif

#include <cstring>
#include <string_view>
#include <span>

namespace client_protected
{
	/*
	   ============================================================================
	   ANTI-DEBUG: Detects debugger presence using 5 different methods
	   ============================================================================
	*/
	MARKER_DEF( bool, check_debugger_present )( ) -> bool
	{
#ifdef _WIN32
		/*
		   check 1: IsDebuggerPresent
		*/
		if ( IsDebuggerPresent( ) ) return true;

		/*
		   check 2: CheckRemoteDebuggerPresent
		*/
		BOOL remote_debugger{ FALSE };
		if ( CheckRemoteDebuggerPresent( GetCurrentProcess( ), &remote_debugger ) && remote_debugger )
		{
			return true;
		}

		/*
		   check 3: NtQueryInformationProcess(ProcessDebugPort)
		*/
		auto& mgr{ shadow::syscall_manager_t::instance( ) };
		DWORD_PTR debug_port{ 0 };
		if ( auto result{ mgr.query_information_process(
				GetCurrentProcess( ), 7, &debug_port, sizeof( debug_port ), nullptr ) };
			result && debug_port != 0 )
		{
			return true;
		}

		/*
		   check 4: Hardware breakpoints (DR0-DR7)
		*/
		CONTEXT ctx{ };
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if ( GetThreadContext( GetCurrentThread( ), &ctx ) )
		{
			if ( ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 )
			{
				return true;
			}
		}

		/*
		   check 5: PEB BeingDebugged flag
		*/
		PPEB peb{ reinterpret_cast<PPEB>( __readgsqword( 0x60 ) ) };
		if ( peb && peb->BeingDebugged ) return true;
#endif
		return false;
	}

	/*
	   ============================================================================
	   ANTI-VM: Detects virtual machine presence using 4 different methods
	   ============================================================================
	*/
	MARKER_DEF( bool, check_vm_present )( ) -> bool
	{
#ifdef _WIN32
		/*
		   check 1: CPUID hypervisor bit
		*/
		int cpu_info[4]{ 0 };
		__cpuid( cpu_info, 1 );
		if ( cpu_info[2] & ( 1 << 31 ) ) return true;  // Hypervisor present bit

		/*
		   check 2: CPUID vendor string
		*/
		__cpuid( cpu_info, 0x40000000 );
		char vendor[13]{ 0 };
		std::memcpy( vendor, &cpu_info[1], 4 );
		std::memcpy( vendor + 4, &cpu_info[2], 4 );
		std::memcpy( vendor + 8, &cpu_info[3], 4 );

		if ( std::string_view( vendor ).find( "VMware" ) != std::string_view::npos ||
		     std::string_view( vendor ).find( "VBoxVBox" ) != std::string_view::npos ||
		     std::string_view( vendor ).find( "Microsoft Hv" ) != std::string_view::npos )
		{
			return true;
		}

		/*
		   check 3: Timing attack (RDTSC)
		*/
		uint64_t start{ __rdtsc( ) };
		Sleep( 10 );
		uint64_t end{ __rdtsc( ) };
		uint64_t elapsed{ end - start };

		/*
		   VMs typically have much higher RDTSC values for the same time
		*/
		if ( elapsed > 1000000 ) return true;

		/*
		   check 4: Check for VM registry keys
		*/
		HKEY h_key{ };
		if ( RegOpenKeyExA( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &h_key ) == ERROR_SUCCESS )
		{
			RegCloseKey( h_key );
			return true;
		}
		if ( RegOpenKeyExA( HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &h_key ) == ERROR_SUCCESS )
		{
			RegCloseKey( h_key );
			return true;
		}
#endif
		return false;
	}

	/*
	   ============================================================================
	   PROCESS ENUMERATION: Find process ID by executable name
	   ============================================================================
	*/
	MARKER_DEF( uint32_t, find_process_by_name )( const char* process_name, size_t name_len ) -> uint32_t
	{
#ifdef _WIN32
		if ( !process_name || name_len == 0 ) return 0;

		HANDLE snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) };
		if ( snapshot == INVALID_HANDLE_VALUE ) return 0;

		PROCESSENTRY32W entry{ };
		entry.dwSize = sizeof( entry );

		if ( Process32FirstW( snapshot, &entry ) )
		{
			do
			{
				/*
				   convert wide string to multi-byte for comparison
				*/
				char name[MAX_PATH];
				WideCharToMultiByte( CP_UTF8, 0, entry.szExeFile, -1, name, sizeof( name ), nullptr, nullptr );

				if ( std::string_view( name ) == std::string_view( process_name, name_len ) )
				{
					CloseHandle( snapshot );
					return entry.th32ProcessID;
				}
			} while ( Process32NextW( snapshot, &entry ) );
		}

		CloseHandle( snapshot );
#endif
		return 0;
	}

	/*
	   ============================================================================
	   PE VALIDATION: Validate PE file headers
	   ============================================================================
	*/
	MARKER_DEF( bool, validate_pe )( const uint8_t* pe_data, size_t size ) -> bool
	{
#ifdef _WIN32
		if ( !pe_data || size < sizeof( IMAGE_DOS_HEADER ) ) return false;

		auto dos_header{ reinterpret_cast<const IMAGE_DOS_HEADER*>( pe_data ) };
		if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) return false;

		if ( size < static_cast<size_t>( dos_header->e_lfanew ) + sizeof( IMAGE_NT_HEADERS ) ) return false;

		auto nt_headers{ reinterpret_cast<const IMAGE_NT_HEADERS*>(
			pe_data + dos_header->e_lfanew
		) };
		if ( nt_headers->Signature != IMAGE_NT_SIGNATURE ) return false;

		return true;
#else
		return false;
#endif
	}

	/*
	   ============================================================================
	   PE INJECTION: Complete PE injection into remote process via syscalls
	   CRITICAL: This is the most sensitive function - strips entire injection logic
	   ============================================================================
	*/
	MARKER_DEF( bool, inject_pe )(
		const uint8_t* pe_data,
		size_t pe_size,
		uint32_t entry_rva,
		const char* target_process,
		size_t target_process_len,
		uint64_t* out_base_address
	) -> bool
	{
#ifdef _WIN32
		auto& mgr{ shadow::syscall_manager_t::instance( ) };

		/*
		   validate PE
		*/
		if ( !validate_pe( pe_data, pe_size ) ) return false;

		/*
		   find target process
		*/
		uint32_t pid{ find_process_by_name( target_process, target_process_len ) };
		if ( pid == 0 ) return false;

		auto process_result{ mgr.open_process( pid, PROCESS_ALL_ACCESS ) };
		if ( !process_result ) return false;
		auto& process{ *process_result };

		/*
		   parse PE headers
		*/
		auto dos_header{ reinterpret_cast<const IMAGE_DOS_HEADER*>( pe_data ) };
		auto nt_headers{ reinterpret_cast<const IMAGE_NT_HEADERS*>(
			pe_data + dos_header->e_lfanew
		) };

		size_t image_size{ nt_headers->OptionalHeader.SizeOfImage };

		/*
		   allocate memory for PE
		*/
		auto base_result{ mgr.allocate_memory(
			process.get( ), nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
		) };
		if ( !base_result ) return false;

		void* remote_base{ *base_result };
		if ( out_base_address )
		{
			*out_base_address = reinterpret_cast<uint64_t>( remote_base );
		}

		/*
		   write headers
		*/
		size_t headers_size{ nt_headers->OptionalHeader.SizeOfHeaders };
		if ( !mgr.write_memory( process.get( ), remote_base,
		                       std::span{ pe_data, headers_size } ) )
		{
			return false;
		}

		/*
		   write sections
		*/
		auto section{ IMAGE_FIRST_SECTION( nt_headers ) };
		for ( WORD i{ 0 }; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section )
		{
			if ( section->SizeOfRawData == 0 ) continue;

			void* section_va{ static_cast<uint8_t*>( remote_base ) + section->VirtualAddress };
			if ( !mgr.write_memory( process.get( ), section_va,
			                       std::span{ pe_data + section->PointerToRawData,
			                                 section->SizeOfRawData } ) )
			{
				return false;
			}
		}

		/*
		   process relocations
		*/
		if ( nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0 )
		{
			uint64_t delta{ reinterpret_cast<uint64_t>( remote_base ) -
			               nt_headers->OptionalHeader.ImageBase };

			auto reloc_dir{ nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] };

			/*
			   create a mutable copy of PE data for relocation processing
			*/
			std::vector<uint8_t> pe_copy( pe_data, pe_data + pe_size );

			auto reloc{ reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				pe_copy.data( ) + reloc_dir.VirtualAddress
			) };

			while ( reloc->VirtualAddress )
			{
				uint8_t* dest{ pe_copy.data( ) + reloc->VirtualAddress };
				uint16_t* reloc_data{ reinterpret_cast<uint16_t*>(
					reinterpret_cast<uint8_t*>( reloc ) + sizeof( IMAGE_BASE_RELOCATION )
				) };

				uint32_t num_entries{ ( reloc->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( uint16_t ) };

				for ( uint32_t i{ 0 }; i < num_entries; ++i )
				{
					uint16_t type{ static_cast<uint16_t>( reloc_data[i] >> 12 ) };
					uint16_t offset{ static_cast<uint16_t>( reloc_data[i] & 0xFFF ) };

					if ( type == IMAGE_REL_BASED_DIR64 )
					{
						uint64_t* patch_addr{ reinterpret_cast<uint64_t*>( dest + offset ) };
						*patch_addr += delta;
					}
				}

				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
					reinterpret_cast<uint8_t*>( reloc ) + reloc->SizeOfBlock
				);
			}

			/*
			   write back relocated image
			*/
			if ( !mgr.write_memory( process.get( ), remote_base,
			                       std::span{ pe_copy.data( ), pe_copy.size( ) } ) )
			{
				return false;
			}
		}

		/*
		   set memory protections
		*/
		if ( !mgr.protect_memory( process.get( ), remote_base, image_size, PAGE_EXECUTE_READ ) )
		{
			return false;
		}

		/*
		   create thread at entry point
		*/
		void* entry{ static_cast<uint8_t*>( remote_base ) +
		            nt_headers->OptionalHeader.AddressOfEntryPoint };
		auto thread_result{ mgr.create_thread( process.get( ), entry, remote_base ) };

		return thread_result.has_value( );
#else
		return false;
#endif
	}

} // namespace client_protected
