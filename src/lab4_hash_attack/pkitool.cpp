#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// Hàm tiện ích: Chuyển cấu trúc ASN1_TIME của OpenSSL sang chuỗi string để in 
std::string asn1_time_to_string(const ASN1_TIME* tm) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "Unknown";
    ASN1_TIME_print(bio, tm);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string res(data, len);
    BIO_free(bio);
    return res;
}

// Trích xuất và in danh sách SANs (Subject Alternative Names)
void print_sans(X509* cert) {
    GENERAL_NAMES* sans = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (!sans) {
        std::cout << "[+] SANs: None\n";
        return;
    }
    std::cout << "[+] Subject Alternative Names (SANs):\n";
    int num = sk_GENERAL_NAME_num(sans);
    for (int i = 0; i < num; ++i) {
        GENERAL_NAME* name = sk_GENERAL_NAME_value(sans, i);
        if (name->type == GEN_DNS) {
            char* dns_str = nullptr;
            ASN1_STRING_to_UTF8((unsigned char**)&dns_str, name->d.dNSName);
            if (dns_str) {
                std::cout << "  - DNS: " << dns_str << "\n";
                OPENSSL_free(dns_str);
            }
        }
    }
    GENERAL_NAMES_free(sans);
}

// Trích xuất và in các quyền hạn sử dụng khóa (Key Usage) 
void print_key_usage(X509* cert) {
    uint32_t usage = X509_get_key_usage(cert);
    if (usage == UINT32_MAX) {
        std::cout << "[+] Key Usage: Not Specified\n";
        return;
    }
    std::cout << "[+] Key Usage: ";
    if (usage & KU_DIGITAL_SIGNATURE) std::cout << "Digital Signature, ";
    if (usage & KU_NON_REPUDIATION) std::cout << "Non-Repudiation, ";
    if (usage & KU_KEY_ENCIPHERMENT) std::cout << "Key Encipherment, ";
    if (usage & KU_DATA_ENCIPHERMENT) std::cout << "Data Encipherment, ";
    if (usage & KU_KEY_AGREEMENT) std::cout << "Key Agreement, ";
    if (usage & KU_KEY_CERT_SIGN) std::cout << "Certificate Signing, ";
    if (usage & KU_CRL_SIGN) std::cout << "CRL Signing, ";
    std::cout << "\n";
}

void print_usage() {
    std::cout << "Usage: pkitool --in <cert.pem> [--issuer-key <public_key.pem>]\n";
}

int main(int argc, char* argv[]) {
    std::string cert_file;
    std::string issuer_key_file;

    // Phân tích cú pháp cờ lệnh CLI 
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--in" && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (arg == "--issuer-key" && i + 1 < argc) {
            issuer_key_file = argv[++i];
        } else {
            print_usage();
            return 1;
        }
    }

    if (cert_file.empty()) {
        std::cerr << "[-] Error: Thieu tham so bat buoc --in\n";
        print_usage();
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Đọc file chứng chỉ PEM 
    FILE* fp = fopen(cert_file.c_str(), "r");
    if (!fp) {
        std::cerr << "[-] Error: Khong the mo file chung chi: " << cert_file << "\n";
        return 1;
    }
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!cert) {
        std::cerr << "[-] Error: Tep tin khong dung dinh dang X.509 chuẩn.\n";
        return 1;
    }

    std::cout << "\n==================================================\n";
    std::cout << "          X.509 CERTIFICATE ANALYSIS\n";
    std::cout << "==================================================\n";

    // 1. Trích xuất Subject & Issuer 
    char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    std::cout << "[+] Subject : " << (subj ? subj : "Unknown") << "\n";
    std::cout << "[+] Issuer  : " << (issuer ? issuer : "Unknown") << "\n";
    if (subj) OPENSSL_free(subj);
    if (issuer) OPENSSL_free(issuer);

    // 2. Trích xuất Hạn sử dụng (Validity Period) 
    std::cout << "[+] Validity Period:\n";
    std::cout << "  - Not Before: " << asn1_time_to_string(X509_get0_notBefore(cert)) << "\n";
    std::cout << "  - Not After : " << asn1_time_to_string(X509_get0_notAfter(cert)) << "\n";

    // 3. Trích xuất thông tin Khóa công khai (Subject Public Key Info) 
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (pubkey) {
        int type = EVP_PKEY_id(pubkey);
        int bits = EVP_PKEY_bits(pubkey);
        std::cout << "[+] Subject Public Key Info:\n";
        std::cout << "  - Algorithm: " << OBJ_nid2ln(type) << "\n";
        std::cout << "  - Key Size : " << bits << " bits\n";
        EVP_PKEY_free(pubkey);
    } else {
        std::cout << "[-] Subject Public Key Info: Failed to extract\n";
    }

    // 4. Signature Algorithm
    int sig_nid = X509_get_signature_nid(cert);
    std::cout << "[+] Signature Algorithm: " << OBJ_nid2ln(sig_nid) << "\n";

    print_key_usage(cert);

    print_sans(cert);

    // Signature Verification
    std::cout << "--------------------------------------------------\n";
    if (!issuer_key_file.empty()) {
        // Trường hợp 1: Có cung cấp khóa của bên cấp phát (Issuer) để check chéo
        FILE* kfp = fopen(issuer_key_file.c_str(), "r");
        if (!kfp) {
            std::cerr << "[-] Error: Khong mo duoc file public key cua Issuer: " << issuer_key_file << "\n";
            X509_free(cert);
            return 1;
        }
        EVP_PKEY* issuer_pubkey = PEM_read_PUBKEY(kfp, nullptr, nullptr, nullptr);
        fclose(kfp);

        if (!issuer_pubkey) {
            std::cerr << "[-] Error: Loi doc khoa public key cua Issuer.\n";
            X509_free(cert);
            return 1;
        }

        if (X509_verify(cert, issuer_pubkey) == 1) {
            std::cout << "[PASS] Signature Verification: Valid (Verified with Issuer Public Key)\n";
        } else {
            std::cout << "[FAIL] Signature Verification: Invalid (Verification failed with Issuer Public Key)\n";
        }
        EVP_PKEY_free(issuer_pubkey);
    } else {
        // Trường hợp 2: Tự kiểm tra tính toàn vẹn hoặc cấu trúc tự ký (Self-Signed Check) 
        EVP_PKEY* self_pubkey = X509_get_pubkey(cert);
        if (self_pubkey) {
            if (X509_verify(cert, self_pubkey) == 1) {
                std::cout << "[PASS] Signature Verification: Valid (Self-Signed Certificate)\n";
            } else {
                std::cout << "[FAIL] Signature Verification: Fail (Requires external CA issuer public key via --issuer-key)\n";
            }
            EVP_PKEY_free(self_pubkey);
        }
    }
    std::cout << "==================================================\n\n";

    X509_free(cert);
    return 0;
}