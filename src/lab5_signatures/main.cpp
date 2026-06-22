#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

std::vector<unsigned char> from_hex(const std::string& hex);
std::vector<unsigned char> read_binary_file(const std::string& path);
bool write_binary_file(const std::string& path, const std::vector<unsigned char>& data);
std::string to_hex(const std::vector<unsigned char>& data);
std::string to_base64(const std::vector<unsigned char>& data);
std::vector<unsigned char> from_base64(const std::string& b64);

bool generate_rsa_pss_keys(int bits, const std::string& priv_out, const std::string& pub_out);
bool generate_ecdsa_keys(const std::string& priv_out, const std::string& pub_out);
std::vector<unsigned char> sign_message_rsa_pss(const std::vector<unsigned char>& data, EVP_PKEY* priv_key);
bool verify_message_rsa_pss(const std::vector<unsigned char>& data, const std::vector<unsigned char>& sig, EVP_PKEY* pub_key);
std::vector<unsigned char> sign_message_ecdsa(const std::vector<unsigned char>& data, EVP_PKEY* priv_key);
bool verify_message_ecdsa(const std::vector<unsigned char>& data, const std::vector<unsigned char>& sig, EVP_PKEY* pub_key);

void run_negative_tests();

int main(int argc, char* argv[]) {
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();

    if (argc < 2) { 
        std::cout << "Usage: ./sigtool --mode <keygen|sign|verify> --algo <rsa|ecdsa> [options]\n"; 
        std::cout << "       ./sigtool --test\n";
        return 1; 
    }

    std::string mode, algo, text, in_file, out_file, key_file, sig_str, encode_mode = "hex";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) mode = "test";
        else if (strcmp(argv[i], "--mode") == 0) mode = argv[++i];
        else if (strcmp(argv[i], "--algo") == 0) algo = argv[++i];
        else if (strcmp(argv[i], "--text") == 0) text = argv[++i];
        else if (strcmp(argv[i], "--in") == 0) in_file = argv[++i];
        else if (strcmp(argv[i], "--out") == 0) out_file = argv[++i];
        else if (strcmp(argv[i], "--key") == 0) key_file = argv[++i];
        else if (strcmp(argv[i], "--sig") == 0) sig_str = argv[++i];
        else if (strcmp(argv[i], "--encode") == 0) encode_mode = argv[++i];
    }

    if (mode.empty()) { std::cout << "Usage: --mode <keygen|sign|verify> --algo <rsa|ecdsa> [options]\n"; return 1; }

    if (mode == "test") { run_negative_tests(); return 0; }
    if (algo == "rsa-pss-3072" || algo == "rsa") algo = "rsa";
    if (algo == "ecdsa-p256" || algo == "ecdsa") algo = "ecdsa";

    if (mode == "keygen") {
        if (algo == "rsa") return generate_rsa_pss_keys(3072, "rsa_private.pem", "rsa_public.pem") ? 0 : 1;
        if (algo == "ecdsa") return generate_ecdsa_keys("ecdsa_private.pem", "ecdsa_public.pem") ? 0 : 1;
    }

    std::vector<unsigned char> payload;
    if (!in_file.empty()) payload = read_binary_file(in_file);
    else if (!text.empty()) payload.assign(text.begin(), text.end());
    if (payload.empty()) return 1;

    BIO* bk = BIO_new_file(key_file.c_str(), "r"); if (!bk) return 1;
    EVP_PKEY* pkey = (mode == "sign") ? PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL) : PEM_read_bio_PUBKEY(bk, NULL, NULL, NULL);
    BIO_free(bk); if (!pkey) return 1;

    if (mode == "sign") {
        std::vector<unsigned char> sig;
        if (algo == "rsa") sig = sign_message_rsa_pss(payload, pkey);
        else if (algo == "ecdsa") sig = sign_message_ecdsa(payload, pkey);
        if (sig.empty()) { EVP_PKEY_free(pkey); return 1; }
        std::string s_sig = (encode_mode == "base64") ? to_base64(sig) : to_hex(sig);
        if (!out_file.empty()) write_binary_file(out_file, sig);
        else std::cout << "[+] Chu ky so:\n" << s_sig << "\n";
    } else if (mode == "verify") {
        std::vector<unsigned char> sig_bytes = (!out_file.empty()) ? read_binary_file(out_file) : ((encode_mode == "base64") ? from_base64(sig_str) : from_hex(sig_str));
        bool ok = (algo == "rsa") ? verify_message_rsa_pss(payload, sig_bytes, pkey) : verify_message_ecdsa(payload, sig_bytes, pkey);
        std::cout << (ok ? "[SUCCESS] Chu ky HOP LE.\n" : "[FAILED] Chu ky SAI.\n");
    }
    EVP_PKEY_free(pkey); return 0;
}