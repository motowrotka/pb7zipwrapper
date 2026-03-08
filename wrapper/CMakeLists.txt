cmake_minimum_required(VERSION 3.20)
project(PbCryptoLzma C CXX)

# Wymuszenie 32-bitowej kompilacji
if(NOT CMAKE_GENERATOR_PLATFORM)
    set(CMAKE_GENERATOR_PLATFORM Win32)
endif()

# Wymuszenie statycznego runtime (/MT)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(PbCryptoLzma SHARED
    wrapper.cpp
    aes.c

    ../7zip-SDK/C/LzmaEnc.c
    ../7zip-SDK/C/LzmaDec.c
    ../7zip-SDK/C/LzmaLib.c
    ../7zip-SDK/C/LzFind.c
    ../7zip-SDK/C/LzFindMt.c
    ../7zip-SDK/C/LzFindOpt.c
    ../7zip-SDK/C/Threads.c
    ../7zip-SDK/C/Alloc.c
    ../7zip-SDK/C/7zCrc.c
    ../7zip-SDK/C/7zCrcOpt.c
    ../7zip-SDK/C/CpuArch.c
)

target_include_directories(PbCryptoLzma PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../7zip-SDK/C
)

target_compile_definitions(PbCryptoLzma PRIVATE _CRT_SECURE_NO_WARNINGS)

set_target_properties(PbCryptoLzma PROPERTIES
    OUTPUT_NAME "PbCryptoLzma"
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)
