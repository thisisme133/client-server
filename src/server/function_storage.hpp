#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>
#include <span>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <optional>
#include <string>

namespace fs = std::filesystem;

namespace server
{
	/**
	 * @brief compute checksum for integrity (matches client-side implementation)
	 * @param data data to checksum
	 * @return checksum value
	 */
	inline auto compute_checksum( std::span<const uint8_t> data ) noexcept -> uint32_t
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
	 * @brief function storage class - loads from patcher output
	 */
	class function_storage_t
	{
		/**
		 * @brief function information structure
		 */
		struct function_info_t
		{
			uint32_t marker_hash{ };
			std::string name{ };
			std::string filename{ };
			std::vector<uint8_t> bytecode{ };
			size_t size{ };
			uint32_t checksum{ };
		};

		std::unordered_map<uint32_t, function_info_t> m_functions{ };
		fs::path m_functions_dir{ };

	public:
		/**
		 * @brief default constructor
		 */
		function_storage_t( ) = default;

		/**
		 * @brief load functions from directory created by function_patcher
		 * @param functions_dir directory containing function bytecode and manifest
		 * @return true if loaded successfully
		 */
		auto load_from_directory( const fs::path& functions_dir ) -> bool
		{
			m_functions_dir = functions_dir;

			if ( !fs::exists( functions_dir ) )
			{
				std::cerr << "Functions directory not found: " << functions_dir << "\n";
				return false;
			}

			/*
			   parse manifest.json
			*/
			fs::path manifest_path{ functions_dir / "manifest.json" };
			if ( !fs::exists( manifest_path ) )
			{
				std::cerr << "Manifest not found: " << manifest_path << "\n";
				return false;
			}

			if ( !parse_manifest( manifest_path ) )
			{
				std::cerr << "Failed to parse manifest\n";
				return false;
			}

			/*
			   load bytecode for each function
			*/
			for ( auto& [hash, info] : m_functions )
			{
				fs::path bytecode_path{ functions_dir / info.filename };
				if ( !fs::exists( bytecode_path ) )
				{
					std::cerr << "Bytecode file not found: " << bytecode_path << "\n";
					continue;
				}

				std::ifstream file{ bytecode_path, std::ios::binary };
				if ( !file )
				{
					std::cerr << "Failed to open: " << bytecode_path << "\n";
					continue;
				}

				info.bytecode.resize( info.size );
				file.read( reinterpret_cast<char*>( info.bytecode.data( ) ), info.size );

				/*
				   compute checksum for integrity verification
				*/
				info.checksum = compute_checksum( info.bytecode );

				std::cout << "Loaded: " << info.name << " (" << info.size << " bytes, checksum: 0x"
				         << std::hex << info.checksum << std::dec << ")\n";
			}

			std::cout << "Loaded " << m_functions.size( ) << " protected functions\n";
			return !m_functions.empty( );
		}

		/**
		 * @brief get function bytecode
		 * @param marker_hash function marker hash
		 * @return span of bytecode or empty span
		 */
		auto get_function_code( uint32_t marker_hash ) const -> std::span<const uint8_t>
		{
			auto it{ m_functions.find( marker_hash ) };
			if ( it != m_functions.end( ) )
			{
				return std::span{ it->second.bytecode };
			}
			return { };
		}

		/**
		 * @brief function data structure
		 */
		struct function_data_t
		{
			std::string_view name{ };
			std::span<const uint8_t> bytecode{ };
			uint32_t checksum{ };
		};

		/**
		 * @brief get complete function info for secure transmission
		 * @param marker_hash function marker hash
		 * @return function data or nullopt
		 */
		auto get_function_info( uint32_t marker_hash ) const -> std::optional<function_data_t>
		{
			auto it{ m_functions.find( marker_hash ) };
			if ( it != m_functions.end( ) )
			{
				return function_data_t{
					it->second.name,
					std::span{ it->second.bytecode },
					it->second.checksum
				};
			}
			return std::nullopt;
		}

		/**
		 * @brief check if function exists
		 * @param marker_hash function marker hash
		 * @return true if function exists
		 */
		auto has_function( uint32_t marker_hash ) const -> bool
		{
			return m_functions.contains( marker_hash );
		}

		/**
		 * @brief get singleton instance
		 * @return reference to function storage
		 */
		static auto instance( ) -> function_storage_t&
		{
			static function_storage_t storage{ };
			return storage;
		}

	private:
		/**
		 * @brief extract string value from JSON field "key": "value"
		 * @param line JSON line
		 * @param key field key
		 * @return extracted value or empty string
		 */
		auto extract_string_value( const std::string& line, const std::string& key ) -> std::string
		{
			auto key_pos{ line.find( "\"" + key + "\"" ) };
			if ( key_pos == std::string::npos ) return { };

			auto colon_pos{ line.find( ":", key_pos ) };
			if ( colon_pos == std::string::npos ) return { };

			auto start{ line.find( "\"", colon_pos ) };
			if ( start == std::string::npos ) return { };
			start++;

			auto end{ line.find( "\"", start ) };
			if ( end == std::string::npos ) return { };

			return line.substr( start, end - start );
		}

		/**
		 * @brief extract numeric value from JSON field "key": value
		 * @param line JSON line
		 * @param key field key
		 * @return extracted value as string or empty string
		 */
		auto extract_number_value( const std::string& line, const std::string& key ) -> std::string
		{
			auto key_pos{ line.find( "\"" + key + "\"" ) };
			if ( key_pos == std::string::npos ) return { };

			auto colon_pos{ line.find( ":", key_pos ) };
			if ( colon_pos == std::string::npos ) return { };

			auto start{ colon_pos + 1 };

			/*
			   skip whitespace
			*/
			while ( start < line.size( ) && std::isspace( line[start] ) ) start++;

			auto end{ start };
			while ( end < line.size( ) && ( std::isdigit( line[end] ) || line[end] == '-' ) ) end++;

			if ( start >= line.size( ) ) return { };
			return line.substr( start, end - start );
		}

		/**
		 * @brief robust JSON parser for manifest format
		 *
		 * Tolerates extra whitespace, different field orders, and formatting variations
		 * @param manifest_path path to manifest file
		 * @return true if parsed successfully
		 */
		auto parse_manifest( const fs::path& manifest_path ) -> bool
		{
			std::ifstream file{ manifest_path };
			if ( !file )
			{
				std::cerr << "Cannot open manifest file\n";
				return false;
			}

			/*
			   read entire file into a single string
			*/
			std::string content{ ( std::istreambuf_iterator<char>( file ) ),
			                     std::istreambuf_iterator<char>( ) };

			/*
			   parse line by line, accumulating fields
			*/
			std::istringstream stream{ content };
			std::string line{ };
			function_info_t current_func{ };
			bool in_function_object{ false };
			int fields_found{ 0 };

			while ( std::getline( stream, line ) )
			{
				/*
				   remove leading/trailing whitespace
				*/
				line.erase( 0, line.find_first_not_of( " \t\r\n" ) );
				if ( !line.empty( ) )
				{
					line.erase( line.find_last_not_of( " \t\r\n," ) + 1 );
				}

				if ( line.empty( ) ) continue;

				/*
				   detect start of function object
				*/
				if ( line.find( "{" ) != std::string::npos && in_function_object == false )
				{
					in_function_object = true;
					current_func = function_info_t{ };
					fields_found = 0;
					continue;
				}

				/*
				   detect end of function object
				*/
				if ( line.find( "}" ) != std::string::npos && in_function_object )
				{
					/*
					   validate we have all required fields
					*/
					if ( fields_found >= 4 && !current_func.name.empty( ) &&
					     current_func.marker_hash != 0 && !current_func.filename.empty( ) &&
					     current_func.size > 0 )
					{
						/*
						   detect hash collision
						*/
						if ( m_functions.contains( current_func.marker_hash ) )
						{
							std::cerr << "Warning: Hash collision for " << current_func.name
							         << " (hash: 0x" << std::hex << current_func.marker_hash << std::dec << ")\n";
						}

						m_functions[current_func.marker_hash] = current_func;
					}
					else
					{
						std::cerr << "Warning: Incomplete function entry skipped (fields: "
						         << fields_found << ")\n";
					}

					in_function_object = false;
					continue;
				}

				if ( !in_function_object ) continue;

				/*
				   extract fields (order-independent)
				*/
				if ( auto name{ extract_string_value( line, "name" ) }; !name.empty( ) )
				{
					current_func.name = name;
					fields_found++;
				}
				else if ( auto hash_str{ extract_number_value( line, "hash" ) }; !hash_str.empty( ) )
				{
					/*
					   parse hash - simple validation
					*/
					bool valid{ true };
					for ( char c : hash_str )
					{
						if ( !std::isdigit( c ) )
						{
							valid = false;
							break;
						}
					}
					if ( valid )
					{
						current_func.marker_hash = std::stoul( hash_str );
						fields_found++;
					}
					else
					{
						std::cerr << "Warning: Invalid hash value: " << hash_str << "\n";
					}
				}
				else if ( auto filename{ extract_string_value( line, "file" ) }; !filename.empty( ) )
				{
					current_func.filename = filename;
					fields_found++;
				}
				else if ( auto size_str{ extract_number_value( line, "size" ) }; !size_str.empty( ) )
				{
					/*
					   parse size - simple validation
					*/
					bool valid{ true };
					for ( char c : size_str )
					{
						if ( !std::isdigit( c ) )
						{
							valid = false;
							break;
						}
					}
					if ( valid )
					{
						current_func.size = std::stoull( size_str );
						fields_found++;
					}
					else
					{
						std::cerr << "Warning: Invalid size value: " << size_str << "\n";
					}
				}
			}

			if ( m_functions.empty( ) )
			{
				std::cerr << "Error: No valid functions found in manifest\n";
				return false;
			}

			return true;
		}
	};

} // namespace server
