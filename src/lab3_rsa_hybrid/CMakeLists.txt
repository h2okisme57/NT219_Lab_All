add_executable(rsatool rsatool.cpp)
add_executable(benchmark_rsa benchmark_rsa.cpp)

target_link_libraries(rsatool PRIVATE crypto)
target_link_libraries(benchmark_rsa PRIVATE crypto)