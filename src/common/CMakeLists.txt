add_library(common_utils STATIC utils.cpp)
target_link_libraries(common_utils PUBLIC OpenSSL::Crypto)