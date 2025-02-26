cmake_minimum_required(VERSION 3.18.1)

project("jailbreak_root_detection")

set(can_use_assembler TRUE)

# Enable assembly language support
enable_language(ASM)

# Find the Android NDK
if(DEFINED ENV{ANDROID_NDK})
    set(ANDROID_NDK $ENV{ANDROID_NDK})
elseif(DEFINED ENV{ANDROID_NDK_HOME})
    set(ANDROID_NDK $ENV{ANDROID_NDK_HOME})
elseif(DEFINED ENV{NDK_HOME})
    set(ANDROID_NDK $ENV{NDK_HOME})
else()
    message(FATAL_ERROR "Android NDK not found. Please set ANDROID_NDK environment variable.")
endif()

# Create the library with both C++ and assembly implementations
add_library(antifrida SHARED 
    syscall.S 
    antifrida.cpp
)

# Find the log library
find_library(log-lib log)

# Setup include paths for all needed headers
if(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(ANDROID_ARCH "arm")
    set(ANDROID_ARCH_DEFINE "__arm__")
elseif(ANDROID_ABI STREQUAL "arm64-v8a")
    set(ANDROID_ARCH "arm64")
    set(ANDROID_ARCH_DEFINE "__aarch64__")
elseif(ANDROID_ABI STREQUAL "x86")
    set(ANDROID_ARCH "x86")
    set(ANDROID_ARCH_DEFINE "__i386__")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(ANDROID_ARCH "x86_64")
    set(ANDROID_ARCH_DEFINE "__x86_64__")
endif()

# Add NDK-specific includes
target_include_directories(antifrida PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ANDROID_NDK}/sources/android/support/include
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/include
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/include/${ANDROID_ARCH}-linux-android${ANDROID_PLATFORM_LEVEL}
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/local/include
)

# Define architecture macros
target_compile_definitions(antifrida PRIVATE ${ANDROID_ARCH_DEFINE})

# Link against the required libraries
target_link_libraries(antifrida ${log-lib})

# Set some additional compiler flags
target_compile_options(antifrida PRIVATE
    -Wall
    -Werror
    -fno-exceptions
    -fno-rtti
)

# Print debug information about the NDK paths
message(STATUS "Android NDK: ${ANDROID_NDK}")
message(STATUS "Android Architecture: ${ANDROID_ARCH}")
message(STATUS "Android ABI: ${ANDROID_ABI}")
message(STATUS "Android Platform Level: ${ANDROID_PLATFORM_LEVEL}")