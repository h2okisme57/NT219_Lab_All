cmake_minimum_required(VERSION 3.15)
project(NT219_Crypto_Labs VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /O2 /EHsc)
else()
    add_compile_options(-Wall -Wextra -O3 -march=native)
endif()

find_package(OpenSSL REQUIRED)

if(WIN32)
    include_directories("C:/msys64/mingw64/include")
    set(CRYPTOPP_LIBRARY "C:/msys64/mingw64/lib/libcryptopp.a")
else()
    include_directories(/usr/include)
    find_library(CRYPTOPP_LIBRARY NAMES cryptopp REQUIRED)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/common)

add_subdirectory(src/lab1_symmetric)
add_subdirectory(src/lab2_aes_pure)
add_subdirectory(src/lab3_rsa_hybrid)
add_subdirectory(src/lab4_hash_attack)
add_subdirectory(src/lab5_signatures)
add_subdirectory(src/lab6_pqc)