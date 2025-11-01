cmake_minimum_required(VERSION 3.10)
project(FunctionPatcher C)

# Compiler uniquement sur Windows
if(WIN32)
    # Inclure les headers du projet principal
    include_directories(${CMAKE_SOURCE_DIR}/include)

    # Créer l'exécutable
    add_executable(function_patcher function_patcher.c)

    # Lier avec DbgHelp (pour les symboles PDB)
    target_link_libraries(function_patcher dbghelp)

    # Options de compilation
    if(MSVC)
        target_compile_options(function_patcher PRIVATE /W4)
    else()
        target_compile_options(function_patcher PRIVATE -Wall -Wextra)
    endif()

    message(STATUS "Function Patcher tool will be built (Windows only)")
else()
    message(STATUS "Function Patcher tool skipped (Windows only)")
endif()
