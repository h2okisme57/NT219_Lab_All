
# CMAKE LAB 2: PURE C++ AES-128 CTR & XTS (INTEGRATED SUBDIRECTORY)

add_executable(aestool_lab2 main.cpp aes.cpp)
add_executable(benchmark_lab2 benchmark_pure.cpp aes.cpp)

if(MSVC)
    target_compile_options(aestool_lab2 PRIVATE /EHsc /O2 /W3)
    target_compile_options(benchmark_lab2 PRIVATE /EHsc /O2 /W3)
else()
    target_compile_options(aestool_lab2 PRIVATE -Wall -Wextra -O3 -march=native -maes)
    target_compile_options(benchmark_lab2 PRIVATE -Wall -Wextra -O3 -march=native -maes)
endif()