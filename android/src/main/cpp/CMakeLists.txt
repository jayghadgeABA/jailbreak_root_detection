cmake_minimum_required(VERSION 3.18.1)

project("jailbreak_root_detection")

# Enable assembly language support
enable_language(ASM)

# Create the library
add_library(antifrida SHARED 
    syscall.S 
    antifrida.cpp
)

# Find the log library
find_library(log-lib log)

# Link against the required libraries
target_link_libraries(antifrida ${log-lib})