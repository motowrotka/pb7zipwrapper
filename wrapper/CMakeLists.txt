cmake_minimum_required(VERSION 3.20)
project(PbCryptoLzma C CXX)

add_library(PbCryptoLzma SHARED
    wrapper.cpp
    # tu później dodasz AES, np. crypto/aes.c
    ../7zip-SDK/C/LzmaEnc.c
    ../7zip-SDK/C/LzmaDec.c
    ../7zip-SDK/C/LzmaLib.c
)

target_include_directories(PbCryptoLzma PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../7zip-SDK/C
)

set_target_properties(PbCryptoLzma PROPERTIES
    OUTPUT_NAME "PbCryptoLzma"
)
