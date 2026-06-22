#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <oqs/oqs.h>

struct Stats {
    double mean;
    double median;
    double min;
    double max;
    double std_dev;
    double ci_95;       
    double ops_per_sec; 
    double mb_per_sec;  
};

Stats calculate_stats(std::vector<double>& timings, size_t payload_size = 0) {
    Stats s;
    size_t n = timings.size();
    if (n == 0) return {0,0,0,0,0,0,0,0};

    double sum = std::accumulate(timings.begin(), timings.end(), 0.0);
    s.mean = sum / n;

    std::sort(timings.begin(), timings.end());
    s.min = timings.front();
    s.max = timings.back();
    s.median = (n % 2 == 0) ? (timings[n/2 - 1] + timings[n/2]) / 2.0 : timings[n/2];

    double variance = 0.0;
    for (double t : timings) {
        variance += (t - s.mean) * (t - s.mean);
    }
    s.std_dev = std::sqrt(variance / n);
    s.ci_95 = 1.96 * (s.std_dev / std::sqrt(static_cast<double>(n)));
    s.ops_per_sec = (sum > 0) ? (static_cast<double>(n) * 1000.0) / sum : 0;

    if (payload_size > 0) {
        double total_bytes = static_cast<double>(n) * payload_size;
        double total_mb = total_bytes / (1024.0 * 1024.0); 
        double total_seconds = sum / 1000.0;
        s.mb_per_sec = (total_seconds > 0) ? (total_mb / total_seconds) : 0;
    } else {
        s.mb_per_sec = 0;
    }
    return s;
}

void print_header(const std::string& op_label) {
    std::cout << "    " << std::left << std::setw(14) << op_label
              << std::right << std::setw(12) << "Mean (ms)"
              << std::setw(12) << "Median (ms)"
              << std::setw(12) << "StdDev (ms)"
              << std::setw(15) << "95% CI (±ms)"
              << std::setw(18) << "Throughput" << "\n";
}

void print_row(const std::string& name, const Stats& s, bool use_mbs) {
    std::cout << "    " << std::left << std::setw(14) << name
              << std::right << std::setw(12) << std::fixed << std::setprecision(4) << s.mean
              << std::setw(12) << s.median
              << std::setw(12) << s.std_dev
              << std::setw(15) << s.ci_95;
    if (use_mbs) {
        std::cout << std::setw(12) << std::setprecision(2) << s.mb_per_sec << " MB/s\n";
    } else {
        std::cout << std::setw(12) << static_cast<uint64_t>(s.ops_per_sec) << " ops/s\n";
    }
}

// Hàm in mảng dữ liệu thô chuẩn cú pháp Python
void print_python_array(const std::string& var_name, const std::vector<double>& data) {
    std::cout << var_name << " = [";
    for(size_t i = 0; i < data.size(); ++i) {
        std::cout << std::fixed << std::setprecision(4) << data[i];
        if(i < data.size() - 1) std::cout << ", ";
    }
    std::cout << "]\n";
}

void run_advanced_benchmark() {
    std::cout << "================================================================================\n";
    std::cout << "                 ADVANCED CRYPTOGRAPHIC BENCHMARK SUITE                         \n";
    std::cout << "================================================================================\n\n";
    
    // Đã chỉnh số vòng lặp N = 30 đúng theo yêu cầu lấy mẫu
    const int loops = 30;

    std::cout << "[*] Activating system warm-up phase to stabilize CPU frequency and caches...\n";
    auto warm_start = std::chrono::high_resolution_clock::now();
    while (true) {
        auto now = std::chrono::high_resolution_clock::now();
        if (std::chrono::duration<double>(now - warm_start).count() > 1.5) break;
        OQS_KEM *warm_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (warm_kem) {
            uint8_t *kp = new uint8_t[warm_kem->length_public_key];
            uint8_t *ks = new uint8_t[warm_kem->length_secret_key];
            OQS_KEM_keypair(warm_kem, kp, ks);
            delete[] kp; delete[] ks;
            OQS_KEM_free(warm_kem);
        }
    }
    std::cout << "[+] Warm-up phase completed successfully.\n\n";

    std::vector<std::string> kem_algs = { OQS_KEM_alg_ml_kem_512, OQS_KEM_alg_ml_kem_768, OQS_KEM_alg_ml_kem_1024 };
    
    // Lưu trữ raw data để lát in ra cho Python
    std::string python_raw_output = "\n# ================= PYTHON RAW DATA (N=30) =================\n";

    std::cout << "[1] KEY ENCAPSULATION MECHANISM (ML-KEM) PERFORMANCE PROFILES\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    
    for (const auto& alg : kem_algs) {
        OQS_KEM *kem = OQS_KEM_new(alg.c_str());
        if (!kem) continue;

        std::cout << "Algorithm Target: " << kem->method_name << "\n";
        print_header("Operation");

        std::vector<uint8_t> pub(kem->length_public_key);
        std::vector<uint8_t> priv(kem->length_secret_key);
        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss_enc(kem->length_shared_secret);
        std::vector<uint8_t> ss_dec(kem->length_shared_secret);

        std::vector<double> keygen_times, encaps_times, decaps_times;

        for (int i = 0; i < loops; i++) {
            auto t1 = std::chrono::high_resolution_clock::now();
            OQS_KEM_keypair(kem, pub.data(), priv.data());
            auto t2 = std::chrono::high_resolution_clock::now();
            keygen_times.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
        }

        for (int i = 0; i < loops; i++) {
            auto t1 = std::chrono::high_resolution_clock::now();
            OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pub.data());
            auto t2 = std::chrono::high_resolution_clock::now();
            encaps_times.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
        }

        for (int i = 0; i < loops; i++) {
            auto t1 = std::chrono::high_resolution_clock::now();
            OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), priv.data());
            auto t2 = std::chrono::high_resolution_clock::now();
            decaps_times.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
        }

        print_row("Keygen", calculate_stats(keygen_times), false);
        print_row("Encaps", calculate_stats(encaps_times), false);
        print_row("Decaps", calculate_stats(decaps_times), false);
        std::cout << "    -------------------------------------------------------------------\n";

        std::string safe_alg_name = kem->method_name;
        std::replace(safe_alg_name.begin(), safe_alg_name.end(), '-', '_');
        
        std::cout << "    >> Raw Data cho " << kem->method_name << " (Copy vào Python):\n";
        print_python_array(safe_alg_name + "_keygen", keygen_times);
        print_python_array(safe_alg_name + "_encaps", encaps_times);
        print_python_array(safe_alg_name + "_decaps", decaps_times);
        std::cout << "\n";

        OQS_KEM_free(kem);
    }

    std::vector<std::string> sig_algs = { OQS_SIG_alg_ml_dsa_44, OQS_SIG_alg_ml_dsa_65, OQS_SIG_alg_ml_dsa_87 };
    std::vector<std::pair<size_t, std::string>> sizes = {
        {1024, "1_KiB"}, {16384, "16_KiB"}, {1048576, "1_MiB"}, {8388608, "8_MiB"}
    };

    std::cout << "[2] DIGITAL SIGNATURE ALGORITHM (ML-DSA) COMPLEX STRESS TESTING\n";
    std::cout << "--------------------------------------------------------------------------------\n";

    for (const auto& alg : sig_algs) {
        OQS_SIG *sig = OQS_SIG_new(alg.c_str());
        if (!sig) continue;

        std::cout << "Algorithm Target: " << sig->method_name << "\n";

        std::vector<uint8_t> pub(sig->length_public_key);
        std::vector<uint8_t> priv(sig->length_secret_key);
        std::vector<uint8_t> signature(sig->length_signature);
        size_t sig_len = sig->length_signature;

        std::vector<double> dsa_keygen_times;
        for (int i = 0; i < loops; i++) {
            auto t1 = std::chrono::high_resolution_clock::now();
            OQS_SIG_keypair(sig, pub.data(), priv.data());
            auto t2 = std::chrono::high_resolution_clock::now();
            dsa_keygen_times.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
        }
        print_header("Key Operations");
        print_row("DSA Keygen", calculate_stats(dsa_keygen_times), false);
        
        std::string safe_alg_name = sig->method_name;
        std::replace(safe_alg_name.begin(), safe_alg_name.end(), '-', '_');
        print_python_array("    " + safe_alg_name + "_keygen", dsa_keygen_times);
        std::cout << "    -------------------------------------------------------------------\n";

        for (const auto& sz_pair : sizes) {
            size_t sz = sz_pair.first;
            std::string label = sz_pair.second;

            std::vector<uint8_t> msg(sz, 0xAA);
            std::vector<double> sign_times, verify_times;

            for (int i = 0; i < loops; i++) {
                auto t1 = std::chrono::high_resolution_clock::now();
                OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), priv.data());
                auto t2 = std::chrono::high_resolution_clock::now();
                sign_times.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
            }
            
            for (int i = 0; i < loops; i++) {
                auto t1 = std::chrono::high_resolution_clock::now();
                OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), sig_len, pub.data());
                auto t2 = std::chrono::high_resolution_clock::now();
                verify_times.push_back(std::chrono::duration<double, std::milli>(t2 - t1).count());
            }

            std::string readable_label = label;
            std::replace(readable_label.begin(), readable_label.end(), '_', ' ');
            std::cout << "    Payload Tier: " << readable_label << " Stress Test\n";
            print_header("Operation");
            
            bool use_mbs = (sz >= 1048576); 
            print_row("Sign", calculate_stats(sign_times, sz), use_mbs);
            print_row("Verify", calculate_stats(verify_times, sz), use_mbs);
            
            // In mảng cho Python (VD: ML_DSA_44_Sign_1_KiB = [...])
            std::cout << "    >> Raw Data (Copy vào Python):\n";
            print_python_array(safe_alg_name + "_sign_" + label, sign_times);
            print_python_array(safe_alg_name + "_verify_" + label, verify_times);
            std::cout << "    -------------------------------------------------------------------\n";
        }
        std::cout << "\n";
        OQS_SIG_free(sig);
    }
    std::cout << "================================================================================\n";
    std::cout << "               BENCHMARK SUITE EXECUTION COMPLETED SUCCESSFULLY                 \n";
    std::cout << "================================================================================\n";
}

int main() {
    OQS_init();
    run_advanced_benchmark();
    OQS_destroy();
    return 0;
}