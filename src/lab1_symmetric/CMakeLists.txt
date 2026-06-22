add_executable(aestool aestool.cpp)
target_link_libraries(aestool PRIVATE ${CRYPTOPP_LIBRARY} OpenSSL::Crypto)

add_executable(benchmark_aes benchmark_aes.cpp)
target_link_libraries(benchmark_aes PRIVATE ${CRYPTOPP_LIBRARY} OpenSSL::Crypto)