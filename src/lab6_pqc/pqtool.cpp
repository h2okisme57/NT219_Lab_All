#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono> 
#include <oqs/oqs.h>
#include "./third_party/json.hpp"

using json = nlohmann::json;

// Base64 alphabet character set for cryptographic formatting
const std::string B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Standard Base64 encoder implementation
std::string base64_encode(const uint8_t* buf, size_t len) {
    std::string ret; int i = 0, j = 0; uint8_t char_array_3[3], char_array_4[4];
    while (len--) {
        char_array_3[i++] = *(buf++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for(i = 0; (i < 4); i++) ret += B64_CHARS[char_array_4[i]];
            i = 0;
        }
    }
    if (i) {
        for(j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (j = 0; (j < i + 1); j++) ret += B64_CHARS[char_array_4[j]];
        while((i++ < 3)) ret += '=';
    }
    return ret;
}

// Standard Base64 decoder implementation
std::vector<uint8_t> base64_decode(std::string const& encoded_string) {
    size_t in_len = encoded_string.size(); int i = 0, j = 0, in_ = 0; uint8_t char_array_4[4], char_array_3[3]; std::vector<uint8_t> ret;
    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = B64_CHARS.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; (i < 3); i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = B64_CHARS.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }
    return ret;
}

// Write raw binary data directly to disk
void write_file(const std::string& filename, const uint8_t* data, size_t len) {
    std::ofstream out(filename, std::ios::binary);
    if (out.is_open()) {
        out.write(reinterpret_cast<const char*>(data), len);
    }
}

// Read entire binary file into memory buffer
std::vector<uint8_t> read_file(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) return std::vector<uint8_t>();
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

// Wrap raw key materials inside standard PEM boundary lines
void write_pem(const std::string& filename, const std::string& header, const uint8_t* data, size_t len) {
    std::ofstream out(filename);
    if (!out.is_open()) return;
    out << "-----BEGIN " << header << "-----\n";
    std::string b64 = base64_encode(data, len);
    for (size_t i = 0; i < b64.length(); i += 64) {
        out << b64.substr(i, 64) << "\n";
    }
    out << "-----END " << header << "-----\n";
}

// Parse and extract cryptographic data from PEM containers
std::vector<uint8_t> read_pem(const std::string& filename) {
    std::ifstream in(filename);
    if (!in.is_open()) return std::vector<uint8_t>();
    std::string line, b64 = "";
    while (std::getline(in, line)) {
        if (line.find("-----BEGIN") == std::string::npos && line.find("-----END") == std::string::npos) {
            b64 += line;
        }
    }
    return base64_decode(b64);
}

// Helper to look up flag values from argument array
std::string get_arg(int argc, char* argv[], const std::string& flag) {
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == flag) return argv[i + 1];
    }
    return "";
}

// Generate key pairs for ML-DSA or ML-KEM algorithms (Dynamic selection)
void handle_keygen(const std::string& algo, const std::string& pub_path, const std::string& priv_path) {
    if (pub_path.empty() || priv_path.empty() || algo.empty()) {
        std::cerr << "[ERROR] Missing --algo, --pub or --priv paths.\n";
        return;
    }
    
    if (algo.find("mldsa") != std::string::npos) {
        const char* sig_alg = OQS_SIG_alg_ml_dsa_44; // Default
        if (algo == "mldsa-65") sig_alg = OQS_SIG_alg_ml_dsa_65;
        else if (algo == "mldsa-87") sig_alg = OQS_SIG_alg_ml_dsa_87;
        else if (algo != "mldsa-44") { std::cerr << "[ERROR] Unsupported algorithm: " << algo << "\n"; return; }
        
        OQS_SIG *sig = OQS_SIG_new(sig_alg);
        if (!sig) { std::cerr << "[ERROR] Initialization failed for " << algo << "\n"; return; }
        
        std::vector<uint8_t> pub(sig->length_public_key);
        std::vector<uint8_t> priv(sig->length_secret_key);
        OQS_SIG_keypair(sig, pub.data(), priv.data());
        write_pem(pub_path, "PUBLIC KEY", pub.data(), pub.size());
        write_pem(priv_path, "PRIVATE KEY", priv.data(), priv.size());
        std::cout << "[SUCCESS] Generated " << sig->method_name << " keypair.\n";
        OQS_SIG_free(sig);
    } 
    else if (algo.find("mlkem") != std::string::npos) {
        const char* kem_alg = OQS_KEM_alg_ml_kem_512; // Default
        if (algo == "mlkem-768") kem_alg = OQS_KEM_alg_ml_kem_768;
        else if (algo == "mlkem-1024") kem_alg = OQS_KEM_alg_ml_kem_1024;
        else if (algo != "mlkem-512") { std::cerr << "[ERROR] Unsupported algorithm: " << algo << "\n"; return; }
        
        OQS_KEM *kem = OQS_KEM_new(kem_alg);
        if (!kem) { std::cerr << "[ERROR] Initialization failed for " << algo << "\n"; return; }
        
        std::vector<uint8_t> pub(kem->length_public_key);
        std::vector<uint8_t> priv(kem->length_secret_key);
        OQS_KEM_keypair(kem, pub.data(), priv.data());
        write_pem(pub_path, "PUBLIC KEY", pub.data(), pub.size());
        write_pem(priv_path, "PRIVATE KEY", priv.data(), priv.size());
        std::cout << "[SUCCESS] Generated " << kem->method_name << " keypair.\n";
        OQS_KEM_free(kem);
    } else {
        std::cerr << "[ERROR] Unsupported algorithm: " << algo << "\n";
    }
}

// Compute a detached ML-DSA digital signature for an input file
void handle_sign(const std::string& algo, const std::string& in_path, const std::string& out_path, const std::string& priv_path) {
    if (in_path.empty() || out_path.empty() || priv_path.empty()) {
        std::cerr << "[ERROR] Missing mandatory sign arguments.\n";
        return;
    }
    
    const char* sig_alg = OQS_SIG_alg_ml_dsa_44; // Default
    if (algo == "mldsa-65") sig_alg = OQS_SIG_alg_ml_dsa_65;
    else if (algo == "mldsa-87") sig_alg = OQS_SIG_alg_ml_dsa_87;
    
    OQS_SIG *sig = OQS_SIG_new(sig_alg);
    std::vector<uint8_t> priv = read_pem(priv_path);
    std::vector<uint8_t> msg = read_file(in_path);
    if(priv.empty()) { std::cerr << "[ERROR] Failed to read private key.\n"; OQS_SIG_free(sig); return; }
    if(msg.empty()) { std::cerr << "[ERROR] Message file is empty or non-existent.\n"; OQS_SIG_free(sig); return; }
    
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;

    if (OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), priv.data()) == OQS_SUCCESS) {
        write_file(out_path, signature.data(), sig_len);
        std::cout << "[SUCCESS] Created detached " << sig->method_name << " signature.\n";
    } else {
        std::cerr << "[ERROR] Signature generation failed.\n";
    }
    OQS_SIG_free(sig);
}

// Verify a detached ML-DSA digital signature against an input file
void handle_verify(const std::string& algo, const std::string& in_path, const std::string& sig_path, const std::string& pub_path) {
    if (in_path.empty() || sig_path.empty() || pub_path.empty()) {
        std::cerr << "[ERROR] Missing mandatory verify arguments.\n";
        return;
    }
    
    const char* sig_alg = OQS_SIG_alg_ml_dsa_44; // Default
    if (algo == "mldsa-65") sig_alg = OQS_SIG_alg_ml_dsa_65;
    else if (algo == "mldsa-87") sig_alg = OQS_SIG_alg_ml_dsa_87;
    
    OQS_SIG *sig = OQS_SIG_new(sig_alg);
    std::vector<uint8_t> pub = read_pem(pub_path);
    std::vector<uint8_t> msg = read_file(in_path);
    std::vector<uint8_t> signature = read_file(sig_path);

    if(pub.empty() || signature.empty()) {
        std::cerr << "[ERROR] Missing key or signature file.\n";
        OQS_SIG_free(sig);
        return;
    }

    if (OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), signature.size(), pub.data()) == OQS_SUCCESS) {
        std::cout << "[SUCCESS] Verification MATCH (" << sig->method_name << "): Data integrity confirmed.\n";
    } else {
        std::cout << "[FAILURE] Verification FAILED: Invalid signature or corrupted data.\n";
    }
    OQS_SIG_free(sig);
}

// Encapsulate a shared secret key using an ML-KEM public key
void handle_encaps(const std::string& algo, const std::string& pub_path, const std::string& ct_path, const std::string& ss_path) {
    if (pub_path.empty() || ct_path.empty() || ss_path.empty()) {
        std::cerr << "[ERROR] Missing mandatory encaps arguments.\n";
        return;
    }
    
    const char* kem_alg = OQS_KEM_alg_ml_kem_512; // Default
    if (algo == "mlkem-768") kem_alg = OQS_KEM_alg_ml_kem_768;
    else if (algo == "mlkem-1024") kem_alg = OQS_KEM_alg_ml_kem_1024;
    
    OQS_KEM *kem = OQS_KEM_new(kem_alg);
    std::vector<uint8_t> pub = read_pem(pub_path);
    if(pub.empty()) { std::cerr << "[ERROR] Failed to load public key.\n"; OQS_KEM_free(kem); return; }
    
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ct.data(), ss.data(), pub.data()) == OQS_SUCCESS) {
        write_file(ct_path, ct.data(), ct.size());
        write_file(ss_path, ss.data(), ss.size());
        std::cout << "[SUCCESS] " << kem->method_name << " encapsulation complete.\n";
    } else {
        std::cerr << "[ERROR] Encapsulation failed.\n";
    }
    OQS_KEM_free(kem);
}

// Decapsulate a ciphertext using an ML-KEM private key to recover the shared secret
void handle_decaps(const std::string& algo, const std::string& priv_path, const std::string& ct_path, const std::string& ss_path) {
    if (priv_path.empty() || ct_path.empty() || ss_path.empty()) {
        std::cerr << "[ERROR] Missing mandatory decaps arguments.\n";
        return;
    }
    
    const char* kem_alg = OQS_KEM_alg_ml_kem_512; // Default
    if (algo == "mlkem-768") kem_alg = OQS_KEM_alg_ml_kem_768;
    else if (algo == "mlkem-1024") kem_alg = OQS_KEM_alg_ml_kem_1024;
    
    OQS_KEM *kem = OQS_KEM_new(kem_alg);
    std::vector<uint8_t> priv = read_pem(priv_path);
    std::vector<uint8_t> ct = read_file(ct_path);
    if(priv.empty() || ct.empty()) { std::cerr << "[ERROR] Missing key or ciphertext file.\n"; OQS_KEM_free(kem); return; }
    
    std::vector<uint8_t> ss(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, ss.data(), ct.data(), priv.data()) == OQS_SUCCESS) {
        write_file(ss_path, ss.data(), ss.size());
        std::cout << "[SUCCESS] " << kem->method_name << " decapsulation complete.\n";
    } else {
        std::cerr << "[ERROR] Decapsulation failed.\n";
    }
    OQS_KEM_free(kem);
}

// Issue a simplified post-quantum public key certificate
void handle_cert_issue(const std::string& sub_name, const std::string& sub_pub_pem, const std::string& ca_priv_pem, const std::string& out_json) {
    std::vector<uint8_t> sub_pub = read_pem(sub_pub_pem);
    std::vector<uint8_t> ca_priv = read_pem(ca_priv_pem);
    if(sub_pub.empty() || ca_priv.empty()) { std::cerr << "[ERROR] Input keys missing for issuance.\n"; return; }
    
    std::string pub_b64 = base64_encode(sub_pub.data(), sub_pub.size());
    std::string tbs_data = sub_name + pub_b64 + "PQ-CA"; 
    
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;
    OQS_SIG_sign(sig, signature.data(), &sig_len, reinterpret_cast<const uint8_t*>(tbs_data.data()), tbs_data.size(), ca_priv.data());
    
    json cert;
    cert["subject"] = sub_name;
    cert["public_key"] = pub_b64;
    cert["issuer"] = "PQ-CA";
    cert["signature"] = base64_encode(signature.data(), sig_len);
    
    std::ofstream out(out_json);
    if (out.is_open()) {
        out << cert.dump(4);
        std::cout << "[SUCCESS] Formatted PQC JSON certificate created.\n";
    }
    OQS_SIG_free(sig);
}

// Parse and verify a JSON post-quantum certificate
void handle_cert_verify(const std::string& cert_json_path, const std::string& ca_pub_pem) {
    std::ifstream in(cert_json_path);
    if (!in.is_open()) {
        std::cerr << "[ERROR] Cannot open certificate file.\n";
        return;
    }
    
    json cert;
    try {
        cert = json::parse(in);
    } catch (const json::parse_error& e) {
        std::cout << "[FAILURE] Certificate validation FAILED. Invalid JSON format due to extreme tampering!\n";
        return;
    }

    std::vector<uint8_t> ca_pub = read_pem(ca_pub_pem);
    if(ca_pub.empty()) { std::cerr << "[ERROR] CA Public key load failed.\n"; return; }

    if (!cert.contains("subject") || !cert.contains("public_key") || !cert.contains("issuer") || !cert.contains("signature")) {
        std::cout << "[FAILURE] Certificate validation FAILED. Missing required JSON structural elements!\n";
        return;
    }

    std::string tbs_data = cert["subject"].get<std::string>() + cert["public_key"].get<std::string>() + cert["issuer"].get<std::string>();
    std::vector<uint8_t> signature = base64_decode(cert["signature"].get<std::string>());

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (OQS_SIG_verify(sig, reinterpret_cast<const uint8_t*>(tbs_data.data()), tbs_data.size(), signature.data(), signature.size(), ca_pub.data()) == OQS_SUCCESS) {
        std::cout << "[SUCCESS] Certificate validation PASSED. Content is trusted.\n";
    } else {
        std::cout << "[FAILURE] Certificate validation FAILED. Data tampering detected!\n";
    }
    OQS_SIG_free(sig);
}

void handle_run_tests() {
    std::cout << "==================================================\n";
    std::cout << "          AUTOMATED PQC TESTING SUITE             \n";
    std::cout << "==================================================\n";

    std::cout << "[*] Running ML-DSA-44 Functional & Negative Tests...\n";
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    std::vector<uint8_t> dsa_pub(sig->length_public_key);
    std::vector<uint8_t> dsa_priv(sig->length_secret_key);
    OQS_SIG_keypair(sig, dsa_pub.data(), dsa_priv.data());

    std::vector<uint8_t> msg = {'L', 'A', 'B', '6', ' ', 'P', 'Q', 'C'};
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;
    OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), dsa_priv.data());

    // Test 1: Chữ ký đúng -> Phải Pass
    if (OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), sig_len, dsa_pub.data()) == OQS_SUCCESS) {
        std::cout << "  [PASS] Test 1: Normal Signature Verification Success.\n";
    } else {
        std::cout << "  [FAIL] Test 1: Normal Signature Verification Failed.\n";
    }

    std::vector<uint8_t> tampered_msg = msg;
    tampered_msg[0] ^= 0xFF; 
    if (OQS_SIG_verify(sig, tampered_msg.data(), tampered_msg.size(), signature.data(), sig_len, dsa_pub.data()) != OQS_SUCCESS) {
        std::cout << "  [PASS] Test 2: Modified Message Successfully Rejected!\n";
    } else {
        std::cout << "  [FAIL] Test 2: Modified Message Accidentally Accepted.\n";
    }

    std::vector<uint8_t> tampered_sig = signature;
    tampered_sig[0] ^= 0xFF; 
    if (OQS_SIG_verify(sig, msg.data(), msg.size(), tampered_sig.data(), sig_len, dsa_pub.data()) != OQS_SUCCESS) {
        std::cout << "  [PASS] Test 3: Modified Signature Successfully Rejected!\n";
    } else {
        std::cout << "  [FAIL] Test 3: Modified Signature Accidentally Accepted.\n";
    }

    std::vector<uint8_t> tampered_pub = dsa_pub;
    tampered_pub[0] ^= 0xFF; 
    if (OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), sig_len, tampered_pub.data()) != OQS_SUCCESS) {
        std::cout << "  [PASS] Test 4: Modified Public Key Successfully Rejected!\n";
    } else {
        std::cout << "  [FAIL] Test 4: Modified Public Key Accidentally Accepted.\n";
    }
    OQS_SIG_free(sig);

    std::cout << "\n[*] Running ML-KEM-512 Functional & Negative Tests...\n";
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    std::vector<uint8_t> kem_pub(kem->length_public_key);
    std::vector<uint8_t> kem_priv(kem->length_secret_key);
    OQS_KEM_keypair(kem, kem_pub.data(), kem_priv.data());

    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss_encap(kem->length_shared_secret);
    std::vector<uint8_t> ss_decap(kem->length_shared_secret);
    OQS_KEM_encaps(kem, ct.data(), ss_encap.data(), kem_pub.data());

    OQS_KEM_decaps(kem, ss_decap.data(), ct.data(), kem_priv.data());
    if (ss_encap == ss_decap) {
        std::cout << "  [PASS] Test 5: Normal KEM Shared Secrets Match.\n";
    } else {
        std::cout << "  [FAIL] Test 5: Normal KEM Shared Secrets Mismatch.\n";
    }

    std::vector<uint8_t> tampered_ct = ct;
    tampered_ct[0] ^= 0xFF; 
    std::vector<uint8_t> ss_decap_tampered(kem->length_shared_secret);
    OQS_KEM_decaps(kem, ss_decap_tampered.data(), tampered_ct.data(), kem_priv.data());
    if (ss_encap != ss_decap_tampered) { 
        std::cout << "  [PASS] Test 6: Modified Ciphertext Safely Rejected (Secrets Mismatch due to IND-CCA protection)!\n";
    } else {
        std::cout << "  [FAIL] Test 6: Modified Ciphertext Exploded.\n";
    }

    std::vector<uint8_t> wrong_priv(kem->length_secret_key);
    std::vector<uint8_t> dummy_pub(kem->length_public_key);
    OQS_KEM_keypair(kem, dummy_pub.data(), wrong_priv.data()); 
    
    std::vector<uint8_t> ss_decap_wrong_key(kem->length_shared_secret);
    OQS_KEM_decaps(kem, ss_decap_wrong_key.data(), ct.data(), wrong_priv.data());
    if (ss_encap != ss_decap_wrong_key) {
        std::cout << "  [PASS] Test 7: Wrong Private Key Blocked (Secrets Mismatch)!\n";
    } else {
        std::cout << "  [FAIL] Test 7: Wrong Private Key Leaked Data.\n";
    }
    OQS_KEM_free(kem);

    std::cout << "\n[*] Running Mandatory Requirement: Batch Verification (Verify N Signatures)...\n";
    const int BATCH_N = 50; // Số lượng mẫu N >= 30 theo chuẩn Protocol
    OQS_SIG *batch_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    std::vector<uint8_t> b_pub(batch_sig->length_public_key);
    std::vector<uint8_t> b_priv(batch_sig->length_secret_key);
    OQS_SIG_keypair(batch_sig, b_pub.data(), b_priv.data());

    std::vector<std::vector<uint8_t>> batch_msgs(BATCH_N);
    std::vector<std::vector<uint8_t>> batch_sigs(BATCH_N);
    
    for(int i = 0; i < BATCH_N; i++) {
        std::string dummy_text = "Batch Cryptographic Verification Payload Index ID: " + std::to_string(i);
        batch_msgs[i] = std::vector<uint8_t>(dummy_text.begin(), dummy_text.end());
        batch_sigs[i].resize(batch_sig->length_signature);
        size_t out_sig_len = 0;
        OQS_SIG_sign(batch_sig, batch_sigs[i].data(), &out_sig_len, batch_msgs[i].data(), batch_msgs[i].size(), b_priv.data());
    }
    bool batch_verify_ok = true;
    auto b_verify_start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < BATCH_N; i++) {
        if (OQS_SIG_verify(batch_sig, batch_msgs[i].data(), batch_msgs[i].size(), batch_sigs[i].data(), batch_sigs[i].size(), b_pub.data()) != OQS_SUCCESS) {
            batch_verify_ok = false;
            break;
        }
    }
    auto b_verify_end = std::chrono::high_resolution_clock::now();
    double total_b_verify_time = std::chrono::duration<double, std::milli>(b_verify_end - b_verify_start).count();

    if (batch_verify_ok) {
        std::cout << "  [PASS] Test 8: Batch Verification of N=" << BATCH_N << " independent signatures completed.\n";
        std::cout << "         Total Batch Processing Time: " << total_b_verify_time << " ms\n";
        std::cout << "         Average Speed Per Verify Op: " << (total_b_verify_time / BATCH_N) << " ms/op\n";
    } else {
        std::cout << "  [FAIL] Test 8: Batch Verification Integrity Failure Detected.\n";
    }
    OQS_SIG_free(batch_sig);

    std::cout << "\n[*] Running Mandatory Requirement: Batch Decapsulation Timing...\n";
    OQS_KEM *batch_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    std::vector<uint8_t> bk_pub(batch_kem->length_public_key);
    std::vector<uint8_t> bk_priv(batch_kem->length_secret_key);
    OQS_KEM_keypair(batch_kem, bk_pub.data(), bk_priv.data());

    std::vector<std::vector<uint8_t>> batch_cts(BATCH_N, std::vector<uint8_t>(batch_kem->length_ciphertext));
    std::vector<std::vector<uint8_t>> batch_ss_encaps(BATCH_N, std::vector<uint8_t>(batch_kem->length_shared_secret));
    std::vector<std::vector<uint8_t>> batch_ss_decaps(BATCH_N, std::vector<uint8_t>(batch_kem->length_shared_secret));

    // Thực hiện encapsulation N lần trước
    for(int i = 0; i < BATCH_N; i++) {
        OQS_KEM_encaps(batch_kem, batch_cts[i].data(), batch_ss_encaps[i].data(), bk_pub.data());
    }

    auto b_decaps_start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < BATCH_N; i++) {
        OQS_KEM_decaps(batch_kem, batch_ss_decaps[i].data(), batch_cts[i].data(), bk_priv.data());
    }
    auto b_decaps_end = std::chrono::high_resolution_clock::now();
    double total_b_decaps_time = std::chrono::duration<double, std::milli>(b_decaps_end - b_decaps_start).count();

    bool batch_kem_ok = true;
    for(int i = 0; i < BATCH_N; i++) {
        if (batch_ss_encaps[i] != batch_ss_decaps[i]) {
            batch_kem_ok = false;
            break;
        }
    }

    if (batch_kem_ok) {
        std::cout << "  [PASS] Test 9: Batch Decapsulation of N=" << BATCH_N << " ciphertexts passed validation.\n";
        std::cout << "         Total Batch Decapsulation Time: " << total_b_decaps_time << " ms\n";
        std::cout << "         Average Speed Per Decaps Op   : " << (total_b_decaps_time / BATCH_N) << " ms/op\n";
    } else {
        std::cout << "  [FAIL] Test 9: Batch Decapsulation generated key mismatch.\n";
    }
    OQS_KEM_free(batch_kem);

    std::cout << "==================================================\n";
}

int main(int argc, char* argv[]) {
    OQS_init();

    if (argc < 2) {
        std::cerr << "Usage error. Valid modes: keygen, sign, verify, encaps, decaps, issue-cert, verify-cert, run-tests\n";
        OQS_destroy();
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen") {
        handle_keygen(get_arg(argc, argv, "--algo"), get_arg(argc, argv, "--pub"), get_arg(argc, argv, "--priv"));
    } else if (cmd == "sign") {
        handle_sign(get_arg(argc, argv, "--algo"), get_arg(argc, argv, "--in"), get_arg(argc, argv, "--out"), get_arg(argc, argv, "--priv"));
    } else if (cmd == "verify") {
        handle_verify(get_arg(argc, argv, "--algo"), get_arg(argc, argv, "--in"), get_arg(argc, argv, "--sig"), get_arg(argc, argv, "--pub"));
    } else if (cmd == "encaps") {
        handle_encaps(get_arg(argc, argv, "--algo"), get_arg(argc, argv, "--pub"), get_arg(argc, argv, "--ct"), get_arg(argc, argv, "--ss"));
    } else if (cmd == "decaps") {
        handle_decaps(get_arg(argc, argv, "--algo"), get_arg(argc, argv, "--priv"), get_arg(argc, argv, "--ct"), get_arg(argc, argv, "--ss"));
    } else if (cmd == "issue-cert") {
        std::string sub = get_arg(argc, argv, "--subject");
        std::string pub = get_arg(argc, argv, "--pub");
        std::string priv = get_arg(argc, argv, "--priv");
        std::string out = get_arg(argc, argv, "--out");
 
        if (sub.empty()) sub = "Le Minh Hoang"; 
        handle_cert_issue(sub, pub, priv, out);
    } else if (cmd == "verify-cert") {
        handle_cert_verify(get_arg(argc, argv, "--cert"), get_arg(argc, argv, "--pub"));
    } else if (cmd == "run-tests") {
        handle_run_tests();   
    } else {
        std::cerr << "[ERROR] Unknown command mode entered.\n";
    }

    OQS_destroy();
    return 0;
}