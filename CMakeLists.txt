cmake_minimum_required(VERSION 3.25)
project(tcp_game_loader_cpp23 CXX)

# C++23 standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release for maximum performance
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific optimizations
if(MSVC)
    # MSVC optimizations
    add_compile_options(
        /std:c++latest
        /W4
        /O2                 # Maximum optimization
        /Oi                 # Intrinsics
        /Ot                 # Favor fast code
        /GL                 # Whole program optimization
        /GS-                # No security checks (performance)
        /fp:fast            # Fast floating point
        /arch:AVX2          # Use AVX2 if available
        /Zc:__cplusplus     # Correct __cplusplus macro
    )
    add_link_options(/LTCG /OPT:REF /OPT:ICF)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX)
else()
    # GCC/Clang optimizations
    add_compile_options(
        -std=c++23
        -Wall -Wextra -Wpedantic
        -O3                 # Maximum optimization
        -march=native       # Use all CPU features
        -mtune=native       # Tune for current CPU
        -flto               # Link-time optimization
        -ffast-math         # Fast math operations
        -funroll-loops      # Unroll loops
        -finline-functions  # Inline functions
        -fomit-frame-pointer # Remove frame pointer
        -fno-exceptions     # No exceptions (performance)
        -fno-rtti           # No RTTI (performance)
    )
    add_link_options(-flto -s)  # Strip symbols
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Common library (header-only style for inline optimizations)
add_library(common_hpp INTERFACE)
target_include_directories(common_hpp INTERFACE ${CMAKE_SOURCE_DIR}/include)

# Common sources (compiled once, linked to both)
add_library(common STATIC
    src/common/network.cpp
    src/common/packet.cpp
)
target_compile_options(common PRIVATE
    $<$<CONFIG:Release>:-O3 -march=native>
)

# Client executable
if(WIN32)
    add_executable(client
        src/client/client.cpp
        src/client/syscalls.cpp
    )
    target_link_libraries(client common ws2_32)
else()
    add_executable(client
        src/client/client.cpp
    )
    target_link_libraries(client common)
endif()

# Server executable
add_executable(server
    src/server/server.cpp
)
target_link_libraries(server common)

# Platform-specific linking
if(WIN32)
    target_link_libraries(server ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(server Threads::Threads)
    target_link_libraries(client Threads::Threads)
endif()

# IPO/LTO for maximum performance
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)
if(ipo_supported)
    set_property(TARGET client PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET server PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET common PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Strip binaries in Release mode
if(UNIX AND NOT APPLE)
    add_custom_command(TARGET client POST_BUILD
        COMMAND strip -s $<TARGET_FILE:client>
        COMMENT "Stripping client binary"
    )
    add_custom_command(TARGET server POST_BUILD
        COMMAND strip -s $<TARGET_FILE:server>
        COMMENT "Stripping server binary"
    )
endif()

# Function patcher tool (Windows only)
if(WIN32)
    add_executable(function_patcher
        tools/function_patcher.cpp
    )
    target_link_libraries(function_patcher dbghelp)
    target_compile_features(function_patcher PRIVATE cxx_std_23)

    if(ipo_supported)
        set_property(TARGET function_patcher PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# Print build info
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "LTO/IPO: ${ipo_supported}")
