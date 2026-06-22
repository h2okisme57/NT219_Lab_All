#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;
using namespace std::chrono;

const int RUNS = 30;
const int OPS_PER_RUN = 1000;

// Hàm in mảng chuẩn Python
void PrintPythonArray(const string& varName, const vector<double>& times) {
    cout << varName << " = [";
    for (size_t i = 0; i < times.size(); ++i) {
        cout << fixed << setprecision(3) << times[i] << (i == times.size() - 1 ? "" : ", ");
    }
    cout << "]" << endl;
}

// CType: 0 = Bình thường & XTS, 1 = ECB (Không IV), 3 = AEAD (GCM, CCM)
template<class ENC_MODE, class DEC_MODE, int CType = 0>
void RunBench(const string& modeName, const string& sizeLabel, size_t sizeBytes, int keySize = 16) {
    
    // XTS Mode bắt buộc kích thước Key phải gấp đôi (32 bytes cho AES-128 XTS)
    if (modeName == "xts") {
        keySize = 32;
    }

    SecByteBlock key(keySize);
    SecByteBlock iv(AES::BLOCKSIZE);
    memset(key, 0x01, key.size());
    memset(iv, 0x02, iv.size());

    // Cấu hình kích thước IV đặc thù cho từng chế độ AEAD
    if (modeName == "gcm") iv.New(12); // GCM chuẩn nhất là 12 bytes IV
    if (modeName == "ccm") iv.New(11); // CCM chuẩn nhất là 11 bytes IV

    vector<CryptoPP::byte> plaintext(sizeBytes, 0x41);
    vector<CryptoPP::byte> ciphertext(sizeBytes, 0);
    vector<CryptoPP::byte> decrypted(sizeBytes, 0);

    vector<double> encTimes;
    vector<double> decTimes;

    // Định nghĩa kích thước khối chunk nhỏ để tránh lỗi quá tải kích thước của CCM
    size_t chunkSize = (modeName == "ccm" && sizeBytes > 256 * 1024) ? 64 * 1024 : sizeBytes;

    // 1. BENCHMARK TIẾN TRÌNH MÃ HÓA (ENCRYPTION)
    for (int r = 0; r < RUNS; ++r) {
        ENC_MODE enc;
        
        if constexpr (CType == 1) {
            enc.SetKey(key, key.size());
        } else {
            enc.SetKeyWithIV(key, key.size(), iv, iv.size());
        }

        auto start = high_resolution_clock::now();
        for (int op = 0; op < OPS_PER_RUN; ++op) {
            if (modeName == "ccm") {
                // Xử lý chia nhỏ khối dữ liệu đầu vào cho CCM để chống lỗi vượt quá độ dài tối đa
                size_t processed = 0;
                while (processed < sizeBytes) {
                    size_t currentChunk = min(chunkSize, sizeBytes - processed);
                    enc.ProcessData(ciphertext.data() + processed, plaintext.data() + processed, currentChunk);
                    processed += currentChunk;
                }
            } else {
                enc.ProcessData(ciphertext.data(), plaintext.data(), sizeBytes);
            }
        }
        auto end = high_resolution_clock::now();
        encTimes.push_back(duration<double, std::milli>(end - start).count());
    }

    // 2. BENCHMARK TIẾN TRÌNH GIẢI MÃ (DECRYPTION)
    for (int r = 0; r < RUNS; ++r) {
        DEC_MODE dec;
        
        if constexpr (CType == 1) {
            dec.SetKey(key, key.size());
        } else {
            dec.SetKeyWithIV(key, key.size(), iv, iv.size());
        }

        auto start = high_resolution_clock::now();
        for (int op = 0; op < OPS_PER_RUN; ++op) {
            if (modeName == "ccm") {
                size_t processed = 0;
                while (processed < sizeBytes) {
                    size_t currentChunk = min(chunkSize, sizeBytes - processed);
                    dec.ProcessData(decrypted.data() + processed, ciphertext.data() + processed, currentChunk);
                    processed += currentChunk;
                }
            } else {
                dec.ProcessData(decrypted.data(), ciphertext.data(), sizeBytes);
            }
        }
        auto end = high_resolution_clock::now();
        decTimes.push_back(duration<double, std::milli>(end - start).count());
    }

    // Xuất mảng dữ liệu ra console đồng bộ chuẩn Python
    PrintPythonArray(modeName + "_enc_" + sizeLabel, encTimes);
    PrintPythonArray(modeName + "_dec_" + sizeLabel, decTimes);
}

int main() {
    vector<pair<string, size_t>> payloads = {
        {"1KB", 1024}, {"4KB", 4096}, {"16KB", 16384},
        {"256KB", 262144}, {"1MB", 1048576}, {"8MB", 8388608}
    };

    cout << "# ========== FULL AES BENCHMARK (ENC & DEC) FOR PYTHON ==========" << endl;
    cout << "repetitions = list(range(1, 31))" << endl << endl;

    for (const auto& p : payloads) {
        cout << "# --- Payload: " << p.first << " ---" << endl;
        
        // CType = 0: Chế độ thông thường & XTS
        RunBench<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption, 0>("ctr", p.first, p.second);
        RunBench<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption, 0>("cbc", p.first, p.second);
        RunBench<OFB_Mode<AES>::Encryption, OFB_Mode<AES>::Decryption, 0>("ofb", p.first, p.second);
        RunBench<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption, 0>("cfb", p.first, p.second);
        RunBench<XTS_Mode<AES>::Encryption, XTS_Mode<AES>::Decryption, 0>("xts", p.first, p.second);
        
        // CType = 1: Chế độ không dùng IV (ECB)
        RunBench<ECB_Mode<AES>::Encryption, ECB_Mode<AES>::Decryption, 1>("ecb", p.first, p.second);
        
        // CType = 3: Chế độ xác thực AEAD (GCM & CCM)
        RunBench<GCM<AES>::Encryption, GCM<AES>::Decryption, 3>("gcm", p.first, p.second);
        RunBench<CCM<AES, 16>::Encryption, CCM<AES, 16>::Decryption, 3>("ccm", p.first, p.second);
    }

    return 0;
}