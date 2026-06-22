#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <iomanip>

// Crypto++ Headers
#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>

#include "json.hpp"

using json = nlohmann::json;

// Bộ giải phóng bộ nhớ an toàn (RAM Zeroing) chống Memory Dump
struct SecureBytes {
    std::vector<uint8_t> buffer;
    SecureBytes() = default;
    explicit SecureBytes(size_t size) : buffer(size, 0) {}
    ~SecureBytes() {
        if (!buffer.empty()) {
            volatile uint8_t* p = buffer.data();
            size_t size = buffer.size();
            while (size--) { *p++ = 0; }
        }
    }
};

std::string ToHex(const std::vector<uint8_t>& data) {
    std::string hex;
    CryptoPP::StringSource(data.data(), data.size(), true, 
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), false));
    return hex;
}

std::vector<uint8_t> FromHex(const std::string& hex) {
    std::string decoded;
    CryptoPP::StringSource(hex, true, 
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
    return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) throw std::runtime_error("FAIL-CLOSED: Không thể mở file đọc: " + path);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) 
        throw std::runtime_error("FAIL-CLOSED: Lỗi trong quá trình đọc file: " + path);
    return buffer;
}

void WriteFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) throw std::runtime_error("FAIL-CLOSED: Không thể mở file ghi: " + path);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Hàm hỗ trợ in lỗi bằng màu ANSI trực quan
void PrintError(const std::string& msg) {
    std::cerr << "\033[1;31m[FATAL ERROR] " << msg << "\033[0m\n";
}

void PrintWarning(const std::string& msg) {
    std::cout << "\033[1;33m[WARNING] " << msg << "\033[0m\n";
}

// KAT Runner phục vụ quét vectors.json
void RunKAT(const std::string& jsonPath) {
    std::ifstream file(jsonPath);
    if (!file.is_open()) throw std::runtime_error("FAIL-CLOSED: Không tìm thấy file cấu hình kiểm thử tại: " + jsonPath);
    json j;
    file >> j;

    int passed = 0, failed = 0;
    std::cout << "[KAT RUNNER] Đang tiến hành xác thực dữ liệu kiểm chứng...\n";

    for (const auto& test : j["test_cases"]) {
        std::string mode = test["mode"];
        std::vector<uint8_t> key = FromHex(test["key"]);
        std::vector<uint8_t> pt = FromHex(test["plaintext"]);
        std::vector<uint8_t> expected_ct = FromHex(test["ciphertext"]);
        std::vector<uint8_t> iv = test.contains("iv") ? FromHex(test["iv"]) : std::vector<uint8_t>();

        std::vector<uint8_t> ct;
        try {
            std::string upperMode = mode;
            std::transform(upperMode.begin(), upperMode.end(), upperMode.begin(), ::toupper);

            if (upperMode == "ECB") {
                CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKey(key.data(), key.size());
                // Thay thế bằng VectorSink trực tiếp để triệt tiêu lỗi TotalBytesRetrieved
                CryptoPP::StringSource(pt.data(), pt.size(), true, 
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ct)));
            } else if (upperMode == "CBC") {
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
                CryptoPP::StringSource(pt.data(), pt.size(), true, 
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ct)));
            } else if (upperMode == "CTR") {
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
                CryptoPP::StringSource(pt.data(), pt.size(), true, 
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ct), CryptoPP::StreamTransformationFilter::NO_PADDING));
            } else if (upperMode == "OFB") {
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
                CryptoPP::StringSource(pt.data(), pt.size(), true, 
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ct), CryptoPP::StreamTransformationFilter::NO_PADDING));
            } else if (upperMode == "CFB") {
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
                CryptoPP::StringSource(pt.data(), pt.size(), true, 
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(ct), CryptoPP::StreamTransformationFilter::NO_PADDING));
            }

            if (ct == expected_ct) {
                std::cout << "  [CASE " << (passed + failed) << "] " << upperMode << " -> PASS\n";
                passed++;
            } else {
                std::cout << "  [CASE " << (passed + failed) << "] " << upperMode << " -> FAIL (Bản mã sai lệch)\n";
                failed++;
            }
        } catch (const std::exception& e) {
            std::cout << "  [CASE " << (passed + failed) << "] " << mode << " -> EXCEPTION: " << e.what() << "\n";
            failed++;
        }
    }
    std::cout << "\n[KAT SUMMARY] KẾT QUẢ: Passed " << passed << " | Failed " << failed << "\n";
}

int main(int argc, char* argv[]) {
    try {
        std::vector<std::string> args(argv, argv + argc);
        
        if (argc < 2) {
            std::cout << "Sử dụng:\n"
                      << "  aestool encrypt/decrypt --mode <ecb|cbc|ofb|cfb|ctr|gcm|ccm> [options]\n"
                      << "  aestool --kat <path/to/vectors.json>\n";
            return 0;
        }

        auto katIt = std::find(args.begin(), args.end(), "--kat");
        if (katIt != args.end() && (katIt + 1) != args.end()) {
            RunKAT(*(katIt + 1));
            return 0;
        }

        std::string command = args[1];
        if (command != "encrypt" && command != "decrypt") {
            throw std::runtime_error("Lệnh không hợp lệ. Phải là 'encrypt' hoặc 'decrypt'.");
        }

        std::string mode = "gcm";
        std::string inFile = "", outFile = "", textIn = "";
        std::string keyHex = "", keyFile = "";
        std::string ivHex = "";
        bool allowEcb = false;

        for (size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--mode" && i + 1 < args.size()) { mode = args[i + 1]; i++; }
            else if (args[i] == "--in" && i + 1 < args.size()) { inFile = args[i + 1]; i++; }
            else if (args[i] == "--out" && i + 1 < args.size()) { outFile = args[i + 1]; i++; }
            else if (args[i] == "--text" && i + 1 < args.size()) { textIn = args[i + 1]; i++; }
            else if (args[i] == "--key-hex" && i + 1 < args.size()) { keyHex = args[i + 1]; i++; }
            else if (args[i] == "--key" && i + 1 < args.size()) { keyFile = args[i + 1]; i++; }
            else if (args[i] == "--iv" && i + 1 < args.size()) { ivHex = args[i + 1]; i++; }
            else if (args[i] == "--allow-ecb") { allowEcb = true; }
        }

        std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);

        // Nạp dữ liệu đầu vào
        std::vector<uint8_t> inputData;
        if (!textIn.empty()) {
            inputData.assign(textIn.begin(), textIn.end());
        } else if (!inFile.empty()) {
            inputData = ReadFile(inFile);
        } else {
            throw std::runtime_error("FAIL-CLOSED: Thiếu dữ liệu đầu vào. Hãy truyền --text hoặc --in.");
        }

        // Chính sách an toàn nâng cao (Misuse Prevention) đối với ECB
        if (mode == "ecb") {
            PrintWarning("Chế độ ECB không an toàn, làm rò rỉ cấu trúc dữ liệu bản rõ!");
            if (inputData.size() > 16384 && !allowEcb) {
                throw std::runtime_error("FAIL-CLOSED: Kích thước file lớn hơn 16 KiB bị chặn ở chế độ ECB. Sử dụng cờ --allow-ecb để bỏ chặn.");
            }
        }

        // Xử lý nạp Khóa (Key) bảo mật
        SecureBytes keyBuffer;
        if (!keyHex.empty()) {
            keyBuffer.buffer = FromHex(keyHex);
        } else if (!keyFile.empty()) {
            keyBuffer.buffer = ReadFile(keyFile);
        } else {
            throw std::runtime_error("FAIL-CLOSED: Chưa cung cấp Khóa bảo mật (--key hoặc --key-hex).");
        }

        if (keyBuffer.buffer.size() != 16 && keyBuffer.buffer.size() != 24 && keyBuffer.buffer.size() != 32) {
            throw std::runtime_error("FAIL-CLOSED: Độ dài khóa AES không hợp lệ (Phải là 128, 192 hoặc 256 bits).");
        }

        // Xử lý nạp hoặc sinh ngẫu nhiên IV/Nonce an toàn
        std::vector<uint8_t> ivBytes;
        if (mode != "ecb") {
            if (!ivHex.empty()) {
                ivBytes = FromHex(ivHex);
            } else {
                PrintWarning("Thiếu tham số IV. Tiến hành tự sinh dữ liệu ngẫu nhiên an toàn bằng AutoSeededRandomPool...");
                CryptoPP::AutoSeededRandomPool rng;
                ivBytes.resize(16); // Mặc định 16 bytes cho các chế độ cơ bản
                if (mode == "gcm") ivBytes.resize(12); // GCM tối ưu nhất với 12 bytes nonce
                if (mode == "ccm") ivBytes.resize(8);  // CCM an toàn từ 7-13 bytes
                rng.GenerateBlock(ivBytes.data(), ivBytes.size());
                std::cout << "[INFO] IV ngẫu nhiên sinh ra (Hex): " << ToHex(ivBytes) << "\n";
            }
        }

        std::vector<uint8_t> outputData;

        // TIẾN TRÌNH THỰC THI MÃ HÓA
        if (command == "encrypt") {
            if (mode == "ecb") {
                CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKey(keyBuffer.buffer.data(), keyBuffer.buffer.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(outputData)));
            } else if (mode == "cbc") {
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(outputData)));
            } else if (mode == "ctr") {
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(outputData), CryptoPP::StreamTransformationFilter::NO_PADDING));
            } else if (mode == "ofb") {
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(outputData), CryptoPP::StreamTransformationFilter::NO_PADDING));
            } else if (mode == "cfb") {
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::VectorSink(outputData), CryptoPP::StreamTransformationFilter::NO_PADDING));
            } else if (mode == "gcm") {
                CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::AuthenticatedEncryptionFilter(enc, new CryptoPP::VectorSink(outputData)));
            } else if (mode == "ccm") {
                CryptoPP::CCM<CryptoPP::AES>::Encryption enc;
                enc.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                    new CryptoPP::AuthenticatedEncryptionFilter(enc, new CryptoPP::VectorSink(outputData), false, 16));
            } else {
                throw std::runtime_error("FAIL-CLOSED: Chế độ mật mã không được hệ thống hỗ trợ.");
            }

            std::cout << "[SUCCESS] Tiến trình mã hóa thành công.\n";
            if (!outFile.empty()) {
                WriteFile(outFile, outputData);
            } else {
                std::cout << "Bản mã kết xuất (Hex): " << ToHex(outputData) << "\n";
            }
        } 
        else if (command == "decrypt") {
            try {
                if (mode == "ecb") {
                    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
                    dec.SetKey(keyBuffer.buffer.data(), keyBuffer.buffer.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(outputData)));
                } else if (mode == "cbc") {
                    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
                    dec.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(outputData)));
                } else if (mode == "ctr") {
                    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
                    dec.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(outputData), CryptoPP::StreamTransformationFilter::NO_PADDING));
                } else if (mode == "ofb") {
                    CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
                    dec.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(outputData), CryptoPP::StreamTransformationFilter::NO_PADDING));
                } else if (mode == "cfb") {
                    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
                    dec.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::VectorSink(outputData), CryptoPP::StreamTransformationFilter::NO_PADDING));
                } else if (mode == "gcm") {
                    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
                    dec.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::AuthenticatedDecryptionFilter(dec, new CryptoPP::VectorSink(outputData)));
                } else if (mode == "ccm") {
                    CryptoPP::CCM<CryptoPP::AES>::Decryption dec;
                    dec.SetKeyWithIV(keyBuffer.buffer.data(), keyBuffer.buffer.size(), ivBytes.data(), ivBytes.size());
                    CryptoPP::StringSource(inputData.data(), inputData.size(), true,
                        new CryptoPP::AuthenticatedDecryptionFilter(dec, new CryptoPP::VectorSink(outputData), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, 16));
                }
            } catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
                throw std::runtime_error("FAIL-CLOSED: Thẻ xác thực (Authentication Tag) không hợp lệ! Dữ liệu đã bị can thiệp trái phép.");
            }

            std::cout << "[SUCCESS] Tiến trình giải mã hoàn tất.\n";
            if (!outFile.empty()) {
                WriteFile(outFile, outputData);
            } else {
                std::string plainTextStr(outputData.begin(), outputData.end());
                std::cout << "Bản rõ phục hồi: " << plainTextStr << "\n";
            }
        }

    } catch (const std::exception& e) {
        PrintError(e.what());
        return 1;
    }
    return 0;
}