add_executable(sigtool main.cpp sigtool.cpp)
add_executable(benchmark_sig benchmark_sig.cpp sigtool.cpp)

target_link_libraries(sigtool PRIVATE crypto)
target_link_libraries(benchmark_sig PRIVATE crypto)