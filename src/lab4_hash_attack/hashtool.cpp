#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <algorithm>

using namespace CryptoPP;

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    StringSource(bytes.data(), bytes.size(), true, new HexEncoder(new StringSink(hex), false));
    return hex;
}

std::string bytes_to_base64(const std::vector<uint8_t>& bytes) {
    std::string b64;
    StringSource(bytes.data(), bytes.size(), true, new Base64Encoder(new StringSink(b64), false));
    return b64;
}

std::vector<uint8_t> run_hash_truncated(const std::string& algo, const std::string& input, size_t bits) {
    std::vector<uint8_t> digest;
    if (algo == "md5") {
        MD5 hash;
        digest.resize(hash.DigestSize());
        hash.Update((const byte*)input.data(), input.size());
        hash.Final(digest.data());
    } else if (algo == "sha1") {
        SHA1 hash;
        digest.resize(hash.DigestSize());
        hash.Update((const byte*)input.data(), input.size());
        hash.Final(digest.data());
    } else if (algo == "sha256") {
        SHA256 hash;
        digest.resize(hash.DigestSize());
        hash.Update((const byte*)input.data(), input.size());
        hash.Final(digest.data());
    } else {
        SHA512 hash;
        digest.resize(hash.DigestSize());
        hash.Update((const byte*)input.data(), input.size());
        hash.Final(digest.data());
    }

    if (bits == 0) return digest;

    size_t bytes_to_keep = (bits + 7) / 8;
    if (digest.size() > bytes_to_keep) {
        digest.resize(bytes_to_keep);
    }
    if (bits % 8 != 0) {
        uint8_t mask = (1 << (bits % 8)) - 1;
        digest.back() &= mask;
    }
    return digest;
}

void run_birthday_attack(const std::string& algo, size_t bits) {
    std::cout << "[*] Launching Birthday Attack on " << algo << " (Truncated to " << bits << " bits)...\n";
    std::map<std::string, std::string> lookup_table;
    uint64_t attempts = 0;
    
    auto start = std::chrono::high_resolution_clock::now();
    while (true) {
        attempts++;
        std::string current_input = "msg_" + std::to_string(attempts);
        std::vector<uint8_t> hash_bytes = run_hash_truncated(algo, current_input, bits);
        std::string hash_hex = bytes_to_hex(hash_bytes);
        
        if (lookup_table.count(hash_hex)) {
            auto end = std::chrono::high_resolution_clock::now();
            double duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();
            
            std::cout << "[+] Collision Found after " << attempts << " attempts!\n";
            std::cout << "    Input 1   : " << lookup_table[hash_hex] << "\n";
            std::cout << "    Input 2   : " << current_input << "\n";
            std::cout << "    Hash (Hex): " << hash_hex << "\n";
            std::cout << "    Time Taken: " << duration << " seconds\n";
            break;
        }
        lookup_table[hash_hex] = current_input;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage:\n";
        std::cerr << "  " << argv[0] << " hash --algo <md5|sha1|sha256|sha512> --in <file> [--out-format <hex|base64>]\n";
        std::cerr << "  " << argv[0] << " attack --algo <md5|sha1|sha256> --bits <number>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string algo = "sha256";
    std::string in_file = "";
    std::string out_format = "hex";
    size_t bits = 16;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc) algo = argv[++i];
        else if (arg == "--in" && i + 1 < argc) in_file = argv[++i];
        else if (arg == "--bits" && i + 1 < argc) bits = std::stoul(argv[++i]);
        else if (arg == "--out-format" && i + 1 < argc) out_format = argv[++i];
    }

    if (mode == "hash") {
        std::ifstream file(in_file, std::ios::binary);
        if (!file) {
            std::cerr << "Error: Cannot open input file " << in_file << "\n";
            return 1;
        }
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        std::vector<uint8_t> full_hash = run_hash_truncated(algo, content, 0);
        
        if (out_format == "base64") {
            std::cout << bytes_to_base64(full_hash) << "\n";
        } else {
            std::cout << bytes_to_hex(full_hash) << "\n";
        }
    } 
    else if (mode == "attack") {
        run_birthday_attack(algo, bits);
    } 
    else {
        std::cerr << "Unknown mode.\n";
        return 1;
    }

    return 0;
}