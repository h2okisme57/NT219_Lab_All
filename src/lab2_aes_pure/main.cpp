#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <numeric>
#include <cmath>
#include <algorithm>
#include "aes.h"

const int CHUNK_SIZE = 4096;

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 < hex.length()) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
    }
    return bytes;
}

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();   
}

std::vector<uint8_t> ReadFixedFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "[FAIL CLOSED] Error: Cannot open file " << filename << "\n";
        exit(1);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void RunKAT(const std::string& filename) {
    std::cout << "[*] Reading KAT vectors from " << filename << "\n";
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "[-] Error: Cannot open KAT file " << filename << "\n";
        exit(1);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    int passed_count = 0;
    size_t pos = 0;

    while ((pos = content.find("\"key\"", pos)) != std::string::npos) {
        auto extract = [&](const std::string& keyName, size_t start_pos) -> std::string {
            size_t p = content.find("\"" + keyName + "\"", start_pos);
            if (p == std::string::npos) return "";
            p = content.find(":", p);
            if (p == std::string::npos) return "";
            size_t start = content.find("\"", p);
            if (start == std::string::npos) return "";
            start++;
            size_t end = content.find("\"", start);
            if (end == std::string::npos) return "";
            return content.substr(start, end - start);
        };

        std::string key_hex = extract("key", pos);
        std::string pt_hex = extract("plaintext", pos);
        std::string expected_ct = extract("ciphertext", pos);

        if (key_hex.empty() || pt_hex.empty() || expected_ct.empty()) break;

        std::vector<uint8_t> key = HexToBytes(key_hex);
        std::vector<uint8_t> pt = HexToBytes(pt_hex);
        std::vector<uint8_t> expected_ct_bytes = HexToBytes(expected_ct);
        
        // Khởi tạo AES với IV ảo để lách luật
        std::vector<uint8_t> dummy_iv(16, 0);
        AES aes(key.data(), key.size(), dummy_iv.data());
        
        std::vector<uint8_t> result_ct(16, 0);
        
        aes.EncryptBlock(pt.data(), result_ct.data());

        std::string result_hex = BytesToHex(result_ct);
        if (result_hex == expected_ct) {
            passed_count++;
        } else {
            std::cout << "[-] KAT FAILED at Key: " << key_hex << "\n";
            std::cout << "Expected : " << expected_ct << "\n";
            std::cout << "Result   : " << result_hex << "\n";
            exit(1);
        }
        
        pos = content.find("}", pos) + 1; 
    }

    if (passed_count > 0) {
        std::cout << "[+] KAT PASSED: " << passed_count << " vectors verified successfully against FIPS-197!\n";
    } else {
        std::cout << "[-] Error: No vectors found or invalid JSON format.\n";
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: aestool <encrypt|decrypt|--kat|--benchmark> ...\n";
        return 1;
    }

    std::string operation = argv[1];

    if (operation == "--kat") {
        if (argc < 3) {
            std::cerr << "Usage: aestool --kat vectors.json\n";
            return 1;
        }
        RunKAT(argv[2]);
        return 0;
    }
    
    if (operation != "encrypt" && operation != "decrypt" && operation != "--kat") {
        std::cerr << "Error: Invalid operation. Use 'encrypt', 'decrypt', or '--kat'.\n";
        return 1;
    }

    if (argc < 12) {
        std::cerr << "Usage: aestool <encrypt|decrypt> --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin\n";
        return 1;
    }

    std::string keyFile, ivFile, inFile, outFile, mode;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "--key" && i + 1 < argc) keyFile = argv[++i];
        else if (arg == "--iv" && i + 1 < argc) ivFile = argv[++i];
        else if (arg == "--in" && i + 1 < argc) inFile = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outFile = argv[++i];
    }

    if (mode != "ctr" && mode != "xts") {
        std::cerr << "Error: Only 'ctr' and 'xts' modes are supported.\n";
        return 1;
    }

    std::vector<uint8_t> key = ReadFixedFile(keyFile);
    std::vector<uint8_t> iv = ReadFixedFile(ivFile);

    if (mode == "ctr" && key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "[FAIL CLOSED] Error: Key must be 16, 24, or 32 bytes for CTR.\n";
        return 1;
    }
    if (mode == "xts" && key.size() != 32) {
        std::cerr << "[FAIL CLOSED] Error: Key must be exactly 32 bytes (256-bit) for XTS.\n";
        return 1;
    }
    
    if (iv.size() != 16) {
        std::cerr << "[FAIL CLOSED] Error: IV/Tweak must be exactly 16 bytes (128 bits).\n";
        return 1;
    }

    std::ifstream input(inFile, std::ios::binary);
    if (!input) {
        std::cerr << "[FAIL CLOSED] Error: Cannot open input file " << inFile << "\n";
        return 1;
    }
    std::ofstream output(outFile, std::ios::binary);
    if (!output) {
        std::cerr << "[FAIL CLOSED] Error: Cannot open output file " << outFile << "\n";
        return 1;
    }

    const size_t CHUNK_SIZE = 65536;
    std::vector<char> buffer(CHUNK_SIZE);
    auto start_time = std::chrono::high_resolution_clock::now();

    if (mode == "xts") {
        AES aes_xts(key.data(), 16, iv.data());
        const uint8_t* key2 = key.data() + 16;
        
        while (input) {
            input.read(buffer.data(), CHUNK_SIZE);
            std::streamsize bytesRead = input.gcount();
            if (bytesRead <= 0) break;

            std::vector<uint8_t> in_buffer(buffer.data(), buffer.data() + bytesRead);
            std::vector<uint8_t> out_buffer;
            
            if (operation == "encrypt") {
                aes_xts.ProcessXTS(in_buffer, out_buffer, key2, iv.data());
            } else {
                aes_xts.DecryptXTS(in_buffer, out_buffer, key2, iv.data());
            }
            output.write(reinterpret_cast<const char*>(out_buffer.data()), out_buffer.size());
        }
    } else {
        AES aes_ctr(key.data(), key.size(), iv.data());
        while (input) {
            input.read(buffer.data(), CHUNK_SIZE);
            std::streamsize bytesRead = input.gcount();
            if (bytesRead <= 0) break;

            std::vector<uint8_t> in_buffer(buffer.data(), buffer.data() + bytesRead);
            std::vector<uint8_t> out_buffer;
            
            aes_ctr.ProcessData(in_buffer, out_buffer);
            output.write(reinterpret_cast<const char*>(out_buffer.data()), out_buffer.size());
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;

    std::cout << "Operation '" << operation << "' completed successfully.\n";
    std::cout << "Time elapsed: " << elapsed.count() << " seconds.\n";

    return 0;
}