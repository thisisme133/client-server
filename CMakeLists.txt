cmake_minimum_required(VERSION 3.10)
project(tcp_client_server C)

set(CMAKE_C_STANDARD 99)

# Optimisations pour binaires minimaux
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE MinSizeRel)
endif()

# Flags de compilation pour réduire la taille
if(MSVC)
    # Windows MSVC
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /Os /GS- /GL")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG /OPT:REF /OPT:ICF")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
elseif(APPLE)
    # macOS (Clang avec linker LLVM)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Os -ffunction-sections -fdata-sections")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-dead_strip")
else()
    # Linux (GCC/Clang avec linker GNU)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Os -ffunction-sections -fdata-sections")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src/common)

# Common library (code partagé)
add_library(common STATIC
    src/common/network.c
    src/common/packet.c
    src/common/compression.c
)

# Server executable
add_executable(server
    src/server/server.c
)
target_link_libraries(server common)

# Client executable
add_executable(client
    src/client/client.c
)
target_link_libraries(client common)

# Linking pour Windows (ws2_32)
if(WIN32)
    target_link_libraries(server ws2_32)
    target_link_libraries(client ws2_32)
endif()

# Strip les symboles en post-build
if(UNIX)
    if(APPLE)
        # macOS : strip sans -s (non supporté)
        add_custom_command(TARGET server POST_BUILD
            COMMAND strip $<TARGET_FILE:server>
            COMMENT "Stripping server binary"
        )
        add_custom_command(TARGET client POST_BUILD
            COMMAND strip $<TARGET_FILE:client>
            COMMENT "Stripping client binary"
        )
    else()
        # Linux : strip avec -s
        add_custom_command(TARGET server POST_BUILD
            COMMAND strip -s $<TARGET_FILE:server>
            COMMENT "Stripping server binary"
        )
        add_custom_command(TARGET client POST_BUILD
            COMMAND strip -s $<TARGET_FILE:client>
            COMMENT "Stripping client binary"
        )
    endif()
endif()
