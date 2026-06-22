#include <cryptopp/rsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <stdexcept>
#include <algorithm>
#include <cctype>

using namespace CryptoPP;

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string read_file(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file: " + filename);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void write_file(const std::string& filename, const std::string& data) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to write file: " + filename);
    out.write(data.data(), data.size());
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> [options]\n";
        return 1;
    }

    std::string command = ToLower(argv[1]);
    std::map<std::string, std::string> args;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.substr(0, 2) == "--" && i + 1 < argc) {
            args[arg] = argv[++i];
        }
    }

    try {
        if (command == "keygen") {
            std::string algo = args.count("--algo") ? ToLower(args["--algo"]) : "rsa";
            std::string priv_path = args.count("--priv") ? args["--priv"] : "priv.key";
            std::string pub_path = args.count("--pub") ? args["--pub"] : "pub.key";
            AutoSeededRandomPool rng;

            if (algo == "rsa") {
                int bits = args.count("--bits") ? std::stoi(args["--bits"]) : 2048;
                InvertibleRSAFunction params;
                params.Initialize(rng, bits);
                RSA::PrivateKey priv(params);
                RSA::PublicKey pub(params);
                
                FileSink priv_file(priv_path.c_str());
                priv.Save(priv_file);
                FileSink pub_file(pub_path.c_str());
                pub.Save(pub_file);
            } else if (algo == "ecdsa") {
                ECDSA<ECP, SHA256>::PrivateKey priv;
                priv.Initialize(rng, ASN1::secp256r1());
                ECDSA<ECP, SHA256>::PublicKey pub;
                priv.MakePublicKey(pub);
                
                FileSink priv_file(priv_path.c_str());
                priv.Save(priv_file);
                FileSink pub_file(pub_path.c_str());
                pub.Save(pub_file);
            }
            std::cout << "[+] Keygen successful.\n";
        }
        else if (command == "sign") {
            std::string algo = args.count("--algo") ? ToLower(args["--algo"]) : "rsa";
            std::string priv_path = args["--priv"];
            std::string in_path = args["--in"];
            std::string sig_path = args["--sig"];
            
            std::string message = read_file(in_path);
            AutoSeededRandomPool rng;
            std::string signature;

            if (algo == "rsa") {
                RSA::PrivateKey priv;
                FileSource priv_file(priv_path.c_str(), true);
                priv.Load(priv_file);
                RSASS<PKCS1v15, SHA256>::Signer signer(priv);
                StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));
            } else if (algo == "ecdsa") {
                ECDSA<ECP, SHA256>::PrivateKey priv;
                FileSource priv_file(priv_path.c_str(), true);
                priv.Load(priv_file);
                ECDSA<ECP, SHA256>::Signer signer(priv);
                StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));
            }
            
            std::string encoded_sig;
            StringSource(signature, true, new Base64Encoder(new StringSink(encoded_sig), false));
            write_file(sig_path, encoded_sig);
            std::cout << "[+] Sign successful.\n";
        }
        else if (command == "verify") {
            std::string algo = args.count("--algo") ? ToLower(args["--algo"]) : "rsa";
            std::string pub_path = args["--pub"];
            std::string in_path = args["--in"];
            std::string sig_path = args["--sig"];
            
            std::string message = read_file(in_path);
            std::string b64_sig = read_file(sig_path);
            std::string signature;
            StringSource(b64_sig, true, new Base64Decoder(new StringSink(signature)));
            
            bool result = false;
            if (algo == "rsa") {
                RSA::PublicKey pub;
                FileSource pub_file(pub_path.c_str(), true);
                pub.Load(pub_file);
                RSASS<PKCS1v15, SHA256>::Verifier verifier(pub);
                SignatureVerificationFilter filter(verifier, new ArraySink((byte*)&result, sizeof(result)), SignatureVerificationFilter::PUT_RESULT);
                StringSource(signature + message, true, new Redirector(filter));
            } else if (algo == "ecdsa") {
                ECDSA<ECP, SHA256>::PublicKey pub;
                FileSource pub_file(pub_path.c_str(), true);
                pub.Load(pub_file);
                ECDSA<ECP, SHA256>::Verifier verifier(pub);
                SignatureVerificationFilter filter(verifier, new ArraySink((byte*)&result, sizeof(result)), SignatureVerificationFilter::PUT_RESULT);
                StringSource(signature + message, true, new Redirector(filter));
            }

            if (result) std::cout << "[+] Verification VALID.\n";
            else std::cout << "[-] Verification INVALID.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}