#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
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

void print_stats(const std::string& algo, const std::string& size_label, double size_mb, const std::vector<double>& times) {
    double sum = std::accumulate(times.begin(), times.end(), 0.0);
    double mean = sum / times.size();
    
    std::vector<double> sorted = times;
    std::sort(sorted.begin(), sorted.end());
    double median = (sorted.size() % 2 == 0) ? 
        (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0 : 
        sorted[sorted.size()/2];
        
    double sq_sum = 0.0;
    for (double v : times) sq_sum += (v - mean) * (v - mean);
    double stdev = std::sqrt(sq_sum / (times.size() > 1 ? times.size() - 1 : 1));
    double ci = 1.96 * (stdev / std::sqrt(times.size()));
    
    double throughput = size_mb / (mean / 1000.0);
    
    std::cout << "| " << std::left << std::setw(10) << algo 
              << " | " << std::setw(10) << size_label 
              << " | " << std::fixed << std::setprecision(2) << std::setw(9) << mean << " ms "
              << " | " << std::setw(9) << median << " ms "
              << " | " << std::setw(9) << stdev << " ms "
              << " | \xB1" << std::setw(7) << ci 
              << " | " << std::setw(11) << throughput << " MB/s |\n";
}

template <class HASH_ALGO>
void run_benchmark(const std::string& algo_name, size_t payload_size, const std::string& size_label) {
    int num_runs = 30;
    std::vector<uint8_t> data(payload_size, 'A');
    std::vector<double> times;
    double size_mb = static_cast<double>(payload_size) / (1024.0 * 1024.0);

    HASH_ALGO hash_warm;
    std::string digest_warm;
    digest_warm.resize(hash_warm.DigestSize());
    for(int i = 0; i < 50; i++) {
        hash_warm.Update(data.data(), data.size());
        hash_warm.Final((byte*)&digest_warm[0]);
    }

    for (int i = 0; i < num_runs; i++) {
        HASH_ALGO hash;
        std::string digest;
        digest.resize(hash.DigestSize());
        
        auto start = high_resolution_clock::now();
        hash.Update(data.data(), data.size());
        hash.Final((byte*)&digest[0]);
        auto end = high_resolution_clock::now();
        
        times.push_back(duration<double, std::milli>(end - start).count());
    }

    print_stats(algo_name, size_label, size_mb, times);
}

int main() {
    std::cout << "LAB 4 - CRYPTOGRAPHIC HASH PERFORMANCE METRICS\n";
    std::cout << "| Algorithm  | File Size  | Mean (ms)    | Median (ms)  | StdDev (ms)  | Sai số    | Throughput  |\n";
    
    run_benchmark<MD5>("MD5", 1024 * 1024, "1 MB");
    run_benchmark<MD5>("MD5", 100 * 1024 * 1024, "100 MB");
    run_benchmark<MD5>("MD5", 500 * 1024 * 1024, "500 MB");
    
    run_benchmark<SHA1>("SHA-1", 1024 * 1024, "1 MB");
    run_benchmark<SHA1>("SHA-1", 100 * 1024 * 1024, "100 MB");
    run_benchmark<SHA1>("SHA-1", 500 * 1024 * 1024, "500 MB");

    run_benchmark<SHA256>("SHA-256", 1024 * 1024, "1 MB");
    run_benchmark<SHA256>("SHA-256", 100 * 1024 * 1024, "100 MB");
    run_benchmark<SHA256>("SHA-256", 500 * 1024 * 1024, "500 MB");

    run_benchmark<SHA512>("SHA-512", 1024 * 1024, "1 MB");
    run_benchmark<SHA512>("SHA-512", 100 * 1024 * 1024, "100 MB");
    run_benchmark<SHA512>("SHA-512", 500 * 1024 * 1024, "500 MB");

    return 0;
}