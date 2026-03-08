cmake_minimum_required(VERSION 3.10)
project(SevenZipWrapper)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Dodajemy katalogi SDK
include_directories(
    ${CMAKE_SOURCE_DIR}/7zip-SDK
    ${CMAKE_SOURCE_DIR}/7zip-SDK/7zip
    ${CMAKE_SOURCE_DIR}/7zip-SDK/Common
    ${CMAKE_SOURCE_DIR}/7zip-SDK/Windows
)

# Wrapper
add_library(SevenZipWrapper SHARED
    wrapper/wrapper.cpp
    wrapper/wrapper.h
)

target_compile_definitions(SevenZipWrapper PRIVATE _UNICODE UNICODE)
