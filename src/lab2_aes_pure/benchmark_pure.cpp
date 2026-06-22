#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <numeric>
#include <cmath>
#include <algorithm>
#include "aes.h"

using namespace std;
using namespace std::chrono;

const int RUNS = 30;

struct StatResult {
    double mean, median, stddev, ci95, throughput;
};

StatResult CalcStats(const vector<double>& times, double sizeMB) {
    size_t n = times.size();
    if (n == 0) return {0,0,0,0,0};

    double sum = accumulate(times.begin(), times.end(), 0.0);
    double mean = sum / n;

    vector<double> sorted = times;
    sort(sorted.begin(), sorted.end());
    double median = (n % 2 == 0) ? (sorted[n/2 - 1] + sorted[n/2]) / 2.0 : sorted[n/2];

    double sq_sum = 0.0;
    for (double v : times) sq_sum += (v - mean) * (v - mean);
    double stddev = sqrt(sq_sum / (n > 1 ? n - 1 : 1));
    double ci95 = 1.96 * (stddev / sqrt(n));

    double throughput = sizeMB / (mean / 1000.0);
    return {mean, median, stddev, ci95, throughput};
}

void PrintPythonArray(const string& varName, const vector<double>& times) {
    cout << varName << " = [";
    for (size_t i = 0; i < times.size(); ++i) {
        cout << fixed << setprecision(3) << times[i] << (i == times.size() - 1 ? "" : ", ");
    }
    cout << "]\n";
}

void RunBenchCTR(size_t sizeBytes, const string& label, const string& varPrefix) {
    vector<uint8_t> key(16, 0xAA); 
    vector<uint8_t> iv(16, 0xBB);
    
    cout << "\n[*] Allocating RAM for " << label << "..." << flush;
    vector<uint8_t> data(sizeBytes, 0x00);
    vector<uint8_t> out_data;
    cout << " Done.\n";

    double sizeMB = sizeBytes / (1024.0 * 1024.0);
    vector<double> encTimes, decTimes;

    // WARM-UP
    ::AES aes_warm(key.data(), key.size(), iv.data());
    auto warmup_start = high_resolution_clock::now();
    while (true) {
        aes_warm.ProcessData(vector<uint8_t>(4096, 0), out_data);
        auto now = high_resolution_clock::now();
        if (duration_cast<seconds>(now - warmup_start).count() >= 1.5) break;
    }

    // ĐO ENCRYPT
    for (int i = 0; i < RUNS; ++i) {
        ::AES aes(key.data(), key.size(), iv.data());
        auto start = high_resolution_clock::now();
        aes.ProcessData(data, out_data);
        auto end = high_resolution_clock::now();
        encTimes.push_back(duration_cast<duration<double, milli>>(end - start).count());
    }

    // ĐO DECRYPT
    for (int i = 0; i < RUNS; ++i) {
        ::AES aes(key.data(), key.size(), iv.data());
        auto start = high_resolution_clock::now();
        aes.ProcessData(out_data, data);
        auto end = high_resolution_clock::now();
        decTimes.push_back(duration_cast<duration<double, milli>>(end - start).count());
    }

    StatResult enc = CalcStats(encTimes, sizeMB);
    StatResult dec = CalcStats(decTimes, sizeMB);
    
    cout << "--------------------------------------------------------------------------------------\n";
    cout << "| " << label << " | Encrypt | " << fixed << setprecision(2) << enc.mean << " ms | " 
         << enc.median << " ms | " << enc.stddev << " ms | \xB1" << enc.ci95 << " | **" << enc.throughput << " MB/s** |\n";
    cout << "| " << label << " | Decrypt | " << fixed << setprecision(2) << dec.mean << " ms | " 
         << dec.median << " ms | " << dec.stddev << " ms | \xB1" << dec.ci95 << " | **" << dec.throughput << " MB/s** |\n";
    cout << "--------------------------------------------------------------------------------------\n\n";

    PrintPythonArray("pure_ctr_enc_" + varPrefix, encTimes);
    PrintPythonArray("pure_ctr_dec_" + varPrefix, decTimes);
}

int main() {
    cout << "### LAB_02\n";
    cout << "| File Size | Operation | Mean (ms) | Median (ms) | StdDev (ms) | 95% CI | Throughput (MB/s) |\n";
    cout << "--------------------------------------------------------------------------------------\n";

    RunBenchCTR(1024 * 1024, "1 MiB", "1MB");
    RunBenchCTR(100 * 1024 * 1024, "100 MiB", "100MB");
    RunBenchCTR(1024 * 1024 * 1024, "1 GiB", "1GB");

    return 0;
}