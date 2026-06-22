#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iomanip>

using namespace CryptoPP;
using namespace std::chrono;

void print_stats(const std::string& name, std::vector<double>& latencies) {
    double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    double mean = sum / latencies.size();
    
    std::vector<double> sorted = latencies;
    std::sort(sorted.begin(), sorted.end());
    double median = (sorted.size() % 2 == 0) ? 
        (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0 : 
        sorted[sorted.size()/2];
        
    double sq_sum = std::inner_product(latencies.begin(), latencies.end(), latencies.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / latencies.size() - mean * mean);
    double ci = 1.96 * (stdev / std::sqrt(latencies.size()));
    
    std::cout << "| " << std::left << std::setw(15) << name 
              << " | " << std::fixed << std::setprecision(2) << std::setw(9) << mean << " ms "
              << " | " << std::setw(9) << median << " ms "
              << " | " << std::setw(9) << stdev << " ms "
              << " | \xB1" << std::setw(7) << ci 
              << " | [95% CI: " << (mean - ci) << ", " << (mean + ci) << "] |\n";
}

void benchmark_rsa(int bits) {
    AutoSeededRandomPool rng;
    int num_runs = 30;

    std::cout << "\n[*] Benchmarking RSA-" << bits << " (N=" << num_runs << ")...\n";
    
    std::vector<double> keygen_times;
    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        InvertibleRSAFunction params;
        params.Initialize(rng, bits, Integer(65537));
        auto end = high_resolution_clock::now();
        keygen_times.push_back(duration<double, std::milli>(end - start).count());
    }
    
    InvertibleRSAFunction params;
    params.Initialize(rng, bits, Integer(65537));
    RSA::PrivateKey priv(params);
    RSA::PublicKey pub(params);
    RSAES_OAEP_SHA256_Encryptor enc(pub);
    RSAES_OAEP_SHA256_Decryptor dec(priv);
    
    std::string msg = "This is a payload test for RSA-OAEP benchmarking.";
    std::string ct;
    ct.resize(enc.CiphertextLength(msg.size()));

    for(int i=0; i<10; i++) enc.Encrypt(rng, (const byte*)msg.data(), msg.size(), (byte*)ct.data());

    std::vector<double> enc_times;
    for(int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < 100; j++) { 
            enc.Encrypt(rng, (const byte*)msg.data(), msg.size(), (byte*)ct.data());
        }
        auto end = high_resolution_clock::now();
        enc_times.push_back(duration<double, std::milli>(end - start).count() / 100.0);
    }

    std::vector<double> dec_times;
    std::string recovered;
    recovered.resize(dec.MaxPlaintextLength(ct.size()));
    for(int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < 100; j++) {
            dec.Decrypt(rng, (const byte*)ct.data(), ct.size(), (byte*)recovered.data());
        }
        auto end = high_resolution_clock::now();
        dec_times.push_back(duration<double, std::milli>(end - start).count() / 100.0);
    }

    print_stats("Keygen", keygen_times);
    print_stats("Encrypt", enc_times);
    print_stats("Decrypt", dec_times);
}

void benchmark_hybrid(size_t payload_size, const std::string& size_label) {
    AutoSeededRandomPool rng;
    int num_runs = 30;

    std::cout << "\n[*] Benchmarking Hybrid Encryption - " << size_label << " (N=" << num_runs << ")...\n";
    
    InvertibleRSAFunction params;
    params.Initialize(rng, 3072, Integer(65537));
    RSA::PublicKey pubKey(params);
    RSAES_OAEP_SHA256_Encryptor rsaEncryptor(pubKey);

    std::string plaintext(payload_size, 'A'); 

    std::vector<double> hybrid_times;
    std::vector<double> throughput_mbs;

    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();

        SecByteBlock aesKey(AES::MAX_KEYLENGTH); 
        SecByteBlock iv(12);
        rng.GenerateBlock(aesKey, aesKey.size());
        rng.GenerateBlock(iv, iv.size());

        std::string aesCiphertext;
        GCM<AES>::Encryption gcm;
        gcm.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());
        StringSource(plaintext, true, new AuthenticatedEncryptionFilter(gcm, new StringSink(aesCiphertext)));

        std::string wrappedKey;
        StringSource(aesKey.data(), aesKey.size(), true, new PK_EncryptorFilter(rng, rsaEncryptor, new StringSink(wrappedKey)));

        auto end = high_resolution_clock::now();
        
        double time_ms = duration<double, std::milli>(end - start).count();
        hybrid_times.push_back(time_ms);
        
        double time_sec = time_ms / 1000.0;
        double size_mb = static_cast<double>(payload_size) / (1024.0 * 1024.0);
        throughput_mbs.push_back(size_mb / time_sec);
    }

    print_stats("Hybrid Latency", hybrid_times);
    
    double sum_thpt = std::accumulate(throughput_mbs.begin(), throughput_mbs.end(), 0.0);
    std::cout << "| Throughput Avg: " << std::fixed << std::setprecision(2) << (sum_thpt / num_runs) << " MB/s |\n";
}

int main() {
    std::cout << "LAB 3 - RSA HYBRID\n";
    std::cout << "| Operation       | Mean (ms)    | Median (ms)  | StdDev (ms)  | Sai số    | Khoảng tin cậy tương ứng         |\n";
    
    benchmark_rsa(3072);
    benchmark_rsa(4096);
    
    benchmark_hybrid(1024, "1 KB");
    benchmark_hybrid(1024 * 1024, "1 MB");
    benchmark_hybrid(100 * 1024 * 1024, "100 MB");

    return 0;
}