cmake_minimum_required(VERSION 3.10)
project(SevenZipWrapper)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

include_directories(${CMAKE_SOURCE_DIR}/7zip-sdk/CPP)

add_library(SevenZipWrapper SHARED
    wrapper/wrapper.cpp
)

target_compile_definitions(SevenZipWrapper PRIVATE _UNICODE UNICODE)
