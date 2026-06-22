# =====================================================================
# CMAKE LAB 1: AES SYMMETRIC ENCRYPTION (CRYPTO++)
# =====================================================================

add_executable(aestool aestool.cpp)
add_executable(benchmark_aes benchmark_aes.cpp)

target_link_libraries(aestool PRIVATE cryptopp)
target_link_libraries(benchmark_aes PRIVATE cryptopp)

if(WIN32)
    if(MSVC)
        target_compile_options(aestool PRIVATE /EHsc /O2 /W3)
        target_compile_options(benchmark_aes PRIVATE /EHsc /O2 /W3)
    else()
        target_compile_options(aestool PRIVATE -g2 -O3 -Wall)
        target_compile_options(benchmark_aes PRIVATE -g2 -O3 -Wall)
        target_link_libraries(aestool PRIVATE ws2_32 crypt32)
        target_link_libraries(benchmark_aes PRIVATE ws2_32 crypt32)
    endif()
else()
    target_compile_options(aestool PRIVATE -g2 -O3 -Wall)
    target_compile_options(benchmark_aes PRIVATE -g2 -O3 -Wall)
    target_link_libraries(aestool PRIVATE pthread)
    target_link_libraries(benchmark_aes PRIVATE pthread)
endif()