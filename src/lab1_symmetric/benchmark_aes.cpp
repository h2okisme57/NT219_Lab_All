#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <string>

using namespace std;
using namespace std::chrono;

const int RUNS = 30;

struct StatResult {
    double mean, median, stddev, ci95;
};

// Hàm tính toán các thông số thống kê cho thông lượng (Throughput)
StatResult CalcStats(const vector<double>& throughputs) {
    size_t n = throughputs.size();
    if (n == 0) return {0,0,0,0};

    double sum = accumulate(throughputs.begin(), throughputs.end(), 0.0);
    double mean = sum / n;

    vector<double> sorted = throughputs;
    sort(sorted.begin(), sorted.end());
    double median = (n % 2 == 0) ? (sorted[n/2 - 1] + sorted[n/2]) / 2.0 : sorted[n/2];

    double sq_sum = 0.0;
    for (double v : throughputs) sq_sum += (v - mean) * (v - mean);
    double stddev = sqrt(sq_sum / (n > 1 ? n - 1 : 1));
    double ci95 = 1.96 * (stddev / sqrt(n));

    return {mean, median, stddev, ci95};
}

// Hàm template thực thi stress test hiệu năng từng chế độ mã hóa
template <typename CipherModeEncryption>
void run_benchmark(const string& mode_name, size_t size_bytes, const string& size_label) {
    // Dùng trực tiếp CryptoPP::byte để tránh xung đột namespace với std::byte trên C++17
    vector<CryptoPP::byte> plaintext(size_bytes, 0x41); // Ký tự 'A'
    vector<CryptoPP::byte> ciphertext(size_bytes, 0);

    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH] = {0};
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0};

    vector<double> throughputs;

    for (int i = 0; i < RUNS; ++i) {
        CipherModeEncryption enc;

        // GIẢI PHÁP TRIỆT ĐỂ: Dùng chế độ nạp tham số động an toàn của Crypto++
        // Nếu thuật toán có IVSize > 0 thì nạp cả Key và IV, ngược lại (như ECB) chỉ nạp Key thuần túy
        if (enc.IVSize() > 0) {
            enc.SetKeyWithIV(key, sizeof(key), iv, enc.IVSize());
        } else {
            enc.SetKey(key, sizeof(key));
        }

        auto start = high_resolution_clock::now();
        
        // Gọi ProcessData xử lý mã hóa tuyến tính trên mảng byte
        enc.ProcessData(ciphertext.data(), plaintext.data(), size_bytes);
        
        auto end = high_resolution_clock::now();
        
        double duration_sec = duration<double>(end - start).count();

        // Tính thông lượng theo băng thông: MB/s = (Bytes / 1024 / 1024) / Giây
        if (duration_sec > 0) {
            double mb_per_sec = (static_cast<double>(size_bytes) / (1024.0 * 1024.0)) / duration_sec;
            throughputs.push_back(mb_per_sec);
        } else {
            throughputs.push_back(0.0);
        }
    }

    StatResult res = CalcStats(throughputs);

    // Xuất kết quả ra console theo định dạng bảng đồng bộ
    cout << "| " << left << setw(12) << mode_name 
         << " | " << setw(9) << size_label 
         << " | " << fixed << setprecision(2) << setw(11) << res.mean 
         << " | " << setw(11) << res.median 
         << " | " << setw(10) << res.stddev 
         << " | [" << setprecision(2) << res.mean - res.ci95 << ", " << res.mean + res.ci95 << "] |\n";
}

int main() {
    cout << "======================================================================================\n";
    cout << "| Che do       | Payload   | Mean (MB/s) | Median (MB/s) | StdDev     | Khoang tin cay 95%     |\n";
    cout << "--------------------------------------------------------------------------------------\n";

    // Danh sách các mức payload kiểm thử stress test CPU
    vector<pair<size_t, string>> sizes = {
        {1024, "1 KB"},
        {4096, "4 KB"},
        {16384, "16 KB"},
        {262144, "266 KB"},
        {1024 * 1024, "1 MB"},
        {8 * 1024 * 1024, "8 MB"}
    };

    // Gọi chạy an toàn không qua ép kiểu compile-time lỗi mẫu
    for (const auto& s : sizes) run_benchmark<CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption>("AES-ECB", s.first, s.second);
    for (const auto& s : sizes) run_benchmark<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption>("AES-CBC", s.first, s.second);
    for (const auto& s : sizes) run_benchmark<CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption>("AES-OFB", s.first, s.second);
    for (const auto& s : sizes) run_benchmark<CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption>("AES-CFB", s.first, s.second);
    for (const auto& s : sizes) run_benchmark<CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption>("AES-CTR", s.first, s.second);

    cout << "======================================================================================\n";
    return 0;
}