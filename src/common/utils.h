#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <string>
#include <cstdint>
#include <iostream>

namespace CryptoCommon {
    struct SecureBuffer {
        std::vector<uint8_t> data;

        SecureBuffer() = default;
        explicit SecureBuffer(size_t size) : data(size, 0) {}
        SecureBuffer(const uint8_t* ptr, size_t size) : data(ptr, ptr + size) {}

        ~SecureBuffer() {
            if (!data.empty()) {
                volatile uint8_t* p = data.data();
                size_t size = data.size();
                while (size--) { *p++ = 0; }
            }
        }
    };

    // Các hàm mã hóa / giải mã chuỗi bổ trợ cho CLI
    std::string ToHex(const std::vector<uint8_t>& buffer);
    std::vector<uint8_t> FromHex(const std::string& hexStr);

    std::string ToBase64(const std::vector<uint8_t>& buffer);
    std::vector<uint8_t> FromBase64(const std::string& b64Str);

    SecureBuffer ReadBinaryFile(const std::string& filepath);
    void WriteBinaryFile(const std::string& filepath, const std::vector<uint8_t>& buffer);
}

#endif