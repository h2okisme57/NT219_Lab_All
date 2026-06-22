include_directories(C:/msys64/mingw64/include)

add_executable(pqtool pqtool.cpp)
add_executable(benchmark_pqc benchmark_pqc.cpp)

if(WIN32)
    target_link_libraries(pqtool PRIVATE oqs ws2_32 crypt32 advapi32)
    target_link_libraries(benchmark_pqc PRIVATE oqs ws2_32 crypt32 advapi32)
else()
    target_link_libraries(pqtool PRIVATE oqs crypto pthread m)
    target_link_libraries(benchmark_pqc PRIVATE oqs crypto pthread m)
endif()