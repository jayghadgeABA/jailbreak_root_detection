cmake_minimum_required(VERSION 3.18.1)

project("jailbreak_root_detection")

# Enable assembly language support
enable_language(ASM)

# Create the library with both C++ and assembly implementations
add_library(antifrida SHARED 
    syscall.S 
    antifrida.cpp
)

# Find the log library
find_library(log-lib log)

# Set architecture-specific definitions
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_compile_definitions(antifrida PRIVATE __arm__)
elseif(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_definitions(antifrida PRIVATE __aarch64__)
elseif(ANDROID_ABI STREQUAL "x86")
    target_compile_definitions(antifrida PRIVATE __i386__)
elseif(ANDROID_ABI STREQUAL "x86_64")
    target_compile_definitions(antifrida PRIVATE __x86_64__)
endif()

# Link against the required libraries
target_link_libraries(antifrida ${log-lib})