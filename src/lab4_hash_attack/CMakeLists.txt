add_executable(hashtool hashtool.cpp)
add_executable(benchmark_hash benchmark_hash.cpp)

target_link_libraries(hashtool PRIVATE crypto)
target_link_libraries(benchmark_hash PRIVATE crypto)