#include <cryptopp/rsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <iomanip>

using namespace CryptoPP;
using namespace std::chrono;

void print_stats(const std::string& algo, const std::string& op, const std::vector<double>& times) {
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
    
    std::cout << "| " << std::left << std::setw(15) << algo 
              << " | " << std::setw(10) << op 
              << " | " << std::fixed << std::setprecision(3) << std::setw(9) << mean << " ms "
              << " | " << std::setw(9) << median << " ms "
              << " | " << std::setw(9) << stdev << " ms "
              << " | \xB1" << std::setw(7) << ci 
              << " | [95% CI: " << (mean - ci) << ", " << (mean + ci) << "] |\n";
}

void benchmark_rsa_sig(int bits, const std::string& name) {
    AutoSeededRandomPool rng;
    int num_runs = 30;
    
    InvertibleRSAFunction params;
    params.Initialize(rng, bits, Integer(65537));
    RSA::PrivateKey priv(params);
    RSA::PublicKey pub(params);
    
    RSASS<PKCS1v15, SHA256>::Signer signer(priv);
    RSASS<PKCS1v15, SHA256>::Verifier verifier(pub);
    
    std::string message = "Payload test data for Digital Signature benchmarking.";
    
    std::string signature;
    signature.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(rng, (const byte*)message.data(), message.size(), (byte*)signature.data());
    signature.resize(sigLen);
    
    for(int i = 0; i < 20; i++) {
        signer.SignMessage(rng, (const byte*)message.data(), message.size(), (byte*)signature.data());
        verifier.VerifyMessage((const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size());
    }
    
    std::vector<double> sign_times;
    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < 50; j++) {
            signer.SignMessage(rng, (const byte*)message.data(), message.size(), (byte*)signature.data());
        }
        auto end = high_resolution_clock::now();
        sign_times.push_back(duration<double, std::milli>(end - start).count() / 50.0);
    }
    
    std::vector<double> verify_times;
    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < 50; j++) {
            verifier.VerifyMessage((const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size());
        }
        auto end = high_resolution_clock::now();
        verify_times.push_back(duration<double, std::milli>(end - start).count() / 50.0);
    }
    
    print_stats(name, "Sign", sign_times);
    print_stats(name, "Verify", verify_times);
}

void benchmark_ecdsa_sig() {
    AutoSeededRandomPool rng;
    int num_runs = 30;
    
    ECDSA<ECP, SHA256>::PrivateKey priv;
    priv.Initialize(rng, ASN1::secp256r1());
    ECDSA<ECP, SHA256>::PublicKey pub;
    priv.MakePublicKey(pub);
    
    ECDSA<ECP, SHA256>::Signer signer(priv);
    ECDSA<ECP, SHA256>::Verifier verifier(pub);
    
    std::string message = "Payload test data for Digital Signature benchmarking.";
    
    std::string signature;
    signature.resize(signer.MaxSignatureLength());
    size_t sigLen = signer.SignMessage(rng, (const byte*)message.data(), message.size(), (byte*)signature.data());
    signature.resize(sigLen);
    
    for(int i = 0; i < 20; i++) {
        signer.SignMessage(rng, (const byte*)message.data(), message.size(), (byte*)signature.data());
        verifier.VerifyMessage((const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size());
    }
    
    std::vector<double> sign_times;
    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < 50; j++) {
            signer.SignMessage(rng, (const byte*)message.data(), message.size(), (byte*)signature.data());
        }
        auto end = high_resolution_clock::now();
        sign_times.push_back(duration<double, std::milli>(end - start).count() / 50.0);
    }
    
    std::vector<double> verify_times;
    for (int i = 0; i < num_runs; i++) {
        auto start = high_resolution_clock::now();
        for(int j = 0; j < 50; j++) {
            verifier.VerifyMessage((const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size());
        }
        auto end = high_resolution_clock::now();
        verify_times.push_back(duration<double, std::milli>(end - start).count() / 50.0);
    }
    
    print_stats("ECDSA P-256", "Sign", sign_times);
    print_stats("ECDSA P-256", "Verify", verify_times);
}

int main() {
    std::cout << "LAB 5 - DIGITAL SIGNATURE PERFORMANCE METRICS\n";
    std::cout << "| Algorithm       | Operation  | Mean (ms)    | Median (ms)  | StdDev (ms)  | Sai số    | Khoảng tin cậy tương ứng         |\n";
    
    benchmark_rsa_sig(2048, "RSA-2048");
    benchmark_rsa_sig(3072, "RSA-3072");
    benchmark_ecdsa_sig();
    
    return 0;
}