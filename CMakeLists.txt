cmake_minimum_required(VERSION 3.20)

# Wymuszenie 32-bitowej kompilacji dla całego projektu
if(NOT CMAKE_GENERATOR_PLATFORM)
    set(CMAKE_GENERATOR_PLATFORM Win32)
endif()

# Wymuszenie statycznego runtime /MT dla całego projektu
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Wyłącz C++ w projekcie nadrzędnym
project(PbCryptoLzma C)

# Dodaj podprojekt wrapper
add_subdirectory(wrapper)
