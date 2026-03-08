cmake_minimum_required(VERSION 3.20)
project(PbCryptoLzma C CXX)

add_library(PbCryptoLzma SHARED
    wrapper.cpp

    # LZMA SDK (C) – komplet wymaganych plików
    ../7zip-SDK/C/LzmaEnc.c
    ../7zip-SDK/C/LzmaDec.c
    ../7zip-SDK/C/LzmaLib.c
    ../7zip-SDK/C/LzFind.c
    ../7zip-SDK/C/LzFindMt.c
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

# Wyłączamy ostrzeżenia o fopen
target_compile_definitions(PbCryptoLzma PRIVATE _CRT_SECURE_NO_WARNINGS)

set_target_properties(PbCryptoLzma PROPERTIES
    OUTPUT_NAME "PbCryptoLzma"
)
