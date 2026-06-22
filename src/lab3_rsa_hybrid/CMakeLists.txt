
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common)

add_executable(rsatool rsatool.cpp)
add_executable(benchmark_rsa benchmark_rsa.cpp)

target_link_libraries(rsatool PRIVATE cryptopp)
target_link_libraries(benchmark_rsa PRIVATE cryptopp)

if(WIN32)
    if(NOT MSVC)
        target_link_libraries(rsatool PRIVATE ws2_32 crypt32)
        target_link_libraries(benchmark_rsa PRIVATE ws2_32 crypt32)
    endif()
endif()