cmake_minimum_required(VERSION 3.16)
project(inkpacket VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# InkPacket library
add_library(inkpacket STATIC
    src/ink_packet_builder.cpp
    src/ink_packet_loader.cpp
    src/ink_packet_patcher.cpp
    src/ink_packet_verify.cpp
    src/ink_packet_memory.cpp
)

target_include_directories(inkpacket PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(inkpacket PUBLIC psyfer)

# Platform-specific sources and libraries
if(UNIX AND NOT APPLE)
    target_sources(inkpacket PRIVATE src/platform/linux.cpp)
    target_link_libraries(inkpacket PRIVATE dl)
elseif(APPLE)
    target_sources(inkpacket PRIVATE src/platform/macos.cpp)
    target_link_libraries(inkpacket PRIVATE dl)
elseif(WIN32)
    target_sources(inkpacket PRIVATE src/platform/windows.cpp)
endif()

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(inkpacket PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -fstack-protector-strong
        -fPIC
    )
endif()

# ink-pack executable
add_executable(ink-pack src/ink_packer.cpp)
target_link_libraries(ink-pack PRIVATE inkpacket)

# ink-patch executable
add_executable(ink-patch src/ink_patch.cpp)
target_link_libraries(ink-patch PRIVATE inkpacket)

# Tests
if(BUILD_TESTING)
    add_executable(test_inkpacket tests/test_inkpacket.cpp)
    target_link_libraries(test_inkpacket PRIVATE inkpacket)
    add_test(NAME inkpacket_test COMMAND test_inkpacket)
endif()