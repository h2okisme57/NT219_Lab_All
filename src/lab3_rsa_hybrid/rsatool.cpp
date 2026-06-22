#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/queue.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <chrono>
#include <map>
#include <cstring>
#include <algorithm>
#include <cctype>

using namespace CryptoPP;

namespace {

enum class KeyMaterialType { UNKNOWN, PUBLIC_KEY, PRIVATE_KEY };
enum class OutputFormat { BINARY, TEXT };
enum class InputMode { TEXT, FILE };

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ParseOutputFormat(const std::string& s, OutputFormat& fmt) {
    const std::string v = ToLower(s);
    if (v == "binary" || v == "bin" || v == "raw") { fmt = OutputFormat::BINARY; return true; }
    if (v == "text" || v == "base64" || v == "b64") { fmt = OutputFormat::TEXT; return true; }
    return false;
}

std::string Base64Encode(const std::string& data) {
    std::string encoded;
    StringSource ss(data, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}

std::string Base64Decode(const std::string& text) {
    std::string decoded;
    StringSource ss(text, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

std::string ReadFileBinary(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open file for reading: " + filename);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void WriteFileBinary(const std::string& filename, const std::string& content) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open file for writing: " + filename);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("Failed to write file: " + filename);
}

bool ContainsPEMMarker(const std::string& content) {
    return content.find("-----BEGIN ") != std::string::npos;
}

struct PEMBlock {
    std::string der;
    KeyMaterialType type = KeyMaterialType::UNKNOWN;
};

PEMBlock DecodePEM(const std::string& pemContent) {
    PEMBlock out;
    const size_t beginPos = pemContent.find("-----BEGIN ");
    if (beginPos == std::string::npos) throw std::runtime_error("PEM begin marker not found");

    const size_t beginEnd = pemContent.find("-----", beginPos + 11);
    if (beginEnd == std::string::npos) throw std::runtime_error("Malformed PEM header");

    const std::string headerType = pemContent.substr(beginPos + 11, beginEnd - (beginPos + 11));
    const std::string endMarker = "-----END " + headerType + "-----";
    const size_t endPos = pemContent.find(endMarker, beginEnd + 5);
    if (endPos == std::string::npos) throw std::runtime_error("Matching PEM end marker not found");

    std::string base64;
    for (size_t i = beginEnd + 5; i < endPos; ++i) {
        const unsigned char ch = static_cast<unsigned char>(pemContent[i]);
        if (!std::isspace(ch)) base64.push_back(static_cast<char>(ch));
    }

    if (base64.empty()) throw std::runtime_error("PEM payload is empty");

    const std::string typeLower = ToLower(headerType);
    if (typeLower == "public key" || typeLower == "rsa public key") {
        out.type = KeyMaterialType::PUBLIC_KEY;
    } else if (typeLower == "private key" || typeLower == "rsa private key") {
        out.type = KeyMaterialType::PRIVATE_KEY;
    } else if (typeLower == "encrypted private key") {
        throw std::runtime_error("Encrypted private key PEM is not supported");
    } else {
        out.type = KeyMaterialType::UNKNOWN;
    }

    out.der = Base64Decode(base64);
    return out;
}

void FillQueue(const std::string& bytes, ByteQueue& q) {
    q.Put(reinterpret_cast<const byte*>(bytes.data()), bytes.size());
    q.MessageEnd();
}

bool TryLoadPublicKeyDER(const std::string& derBytes, RSA::PublicKey& publicKey) {
    try { ByteQueue q; FillQueue(derBytes, q); publicKey.BERDecode(q); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); publicKey.BERDecodePublicKey(q, false, static_cast<CryptoPP::word32>(q.MaxRetrievable())); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); publicKey.Load(q); return true; } catch (...) {}
    return false;
}

bool TryLoadPrivateKeyDER(const std::string& derBytes, RSA::PrivateKey& privateKey) {
    try { ByteQueue q; FillQueue(derBytes, q); privateKey.BERDecode(q); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); privateKey.BERDecodePrivateKey(q, false, static_cast<CryptoPP::word32>(q.MaxRetrievable())); return true; } catch (...) {}
    try { ByteQueue q; FillQueue(derBytes, q); privateKey.Load(q); return true; } catch (...) {}
    return false;
}

RSA::PublicKey LoadEncryptionKeyFromFile(const std::string& keyPath) {
    const std::string fileBytes = ReadFileBinary(keyPath);
    std::string derBytes = fileBytes;
    KeyMaterialType hintedType = KeyMaterialType::UNKNOWN;

    if (ContainsPEMMarker(fileBytes)) {
        PEMBlock pem = DecodePEM(fileBytes);
        derBytes = pem.der;
        hintedType = pem.type;
    }

    AutoSeededRandomPool rng;
    if (hintedType == KeyMaterialType::PUBLIC_KEY || hintedType == KeyMaterialType::UNKNOWN) {
        RSA::PublicKey pub;
        if (TryLoadPublicKeyDER(derBytes, pub) && pub.Validate(rng, 3)) return pub;
    }
    if (hintedType == KeyMaterialType::PRIVATE_KEY || hintedType == KeyMaterialType::UNKNOWN) {
        RSA::PrivateKey priv;
        if (TryLoadPrivateKeyDER(derBytes, priv) && priv.Validate(rng, 3)) {
            RSA::PublicKey pub;
            pub.Initialize(priv.GetModulus(), priv.GetPublicExponent());
            if (!pub.Validate(rng, 3)) throw std::runtime_error("Derived public key validation failed");
            return pub;
        }
    }
    throw std::runtime_error("Failed to load RSA public key from file: " + keyPath);
}

RSA::PrivateKey LoadDecryptionKeyFromFile(const std::string& keyPath) {
    const std::string fileBytes = ReadFileBinary(keyPath);
    std::string derBytes = fileBytes;
    KeyMaterialType hintedType = KeyMaterialType::UNKNOWN;

    if (ContainsPEMMarker(fileBytes)) {
        PEMBlock pem = DecodePEM(fileBytes);
        derBytes = pem.der;
        hintedType = pem.type;
    }

    AutoSeededRandomPool rng;
    if (hintedType == KeyMaterialType::PRIVATE_KEY || hintedType == KeyMaterialType::UNKNOWN) {
        RSA::PrivateKey priv;
        if (TryLoadPrivateKeyDER(derBytes, priv) && priv.Validate(rng, 3)) return priv;
    }
    throw std::runtime_error("Failed to load RSA private key from file: " + keyPath);
}

std::string QueueToString(ByteQueue& queue) {
    std::string out;
    out.resize(queue.CurrentSize());
    queue.Get(reinterpret_cast<byte*>(&out[0]), out.size());
    return out;
}

std::string DERToPEM(const std::string& derBytes, const std::string& header, const std::string& footer) {
    std::string base64;
    StringSource ss(reinterpret_cast<const byte*>(derBytes.data()), derBytes.size(), true, 
                    new Base64Encoder(new StringSink(base64), true, 64));
    return header + "\n" + base64 + footer + "\n";
}

class RSA_App {
public:
    static void KeyGen(uint32_t bits, const std::string& pubPath, const std::string& privPath) {
        if (bits != 3072 && bits != 4096) {
            throw std::invalid_argument("Invalid RSA Modulus size. Standards strictly require 3072 or 4096 bits.");
        }

        AutoSeededRandomPool rng;
        InvertibleRSAFunction params;
        params.Initialize(rng, bits, Integer(65537)); 

        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3))
            throw std::runtime_error("Key validation failed");

        ByteQueue privQ, pubQ;
        privateKey.Save(privQ);
        publicKey.Save(pubQ);

        std::string privDerBytes = QueueToString(privQ);
        std::string pubDerBytes = QueueToString(pubQ);

        WriteFileBinary(pubPath, DERToPEM(pubDerBytes, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"));
        WriteFileBinary(privPath, DERToPEM(privDerBytes, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"));

        auto getBaseName = [](const std::string& path) {
            size_t dot = path.find_last_of('.');
            return (dot == std::string::npos) ? path : path.substr(0, dot);
        };

        std::string pubBase = getBaseName(pubPath);
        std::string privBase = getBaseName(privPath);

        WriteFileBinary(privBase + ".der", privDerBytes);
        WriteFileBinary(pubBase + ".der", pubDerBytes);

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::string meta = "{\n  \"creation_time\": \"" + std::string(std::ctime(&now));
        meta.pop_back(); 
        meta += "\",\n  \"modulus_bits\": " + std::to_string(bits) + ",\n  \"hash\": \"SHA-256\"\n}\n";
        WriteFileBinary("metadata.json", meta);
    }

    static std::string LoadInput(InputMode inputMode, const std::string& inputValue) {
        if (inputMode == InputMode::FILE) return ReadFileBinary(inputValue);
        return inputValue;
    }

    static void EncryptData(InputMode inMode, const std::string& inValue, const std::string& pubKeyPath, const std::string& outFile, OutputFormat outFormat, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PublicKey pubKey = LoadEncryptionKeyFromFile(pubKeyPath);
        std::string plaintext = LoadInput(inMode, inValue);
        
        RSAES_OAEP_SHA256_Encryptor rsaEncryptor(pubKey);
        std::string finalOutput;
        
        if (plaintext.length() <= rsaEncryptor.FixedMaxPlaintextLength()) {
            std::string ciphertext;
            ciphertext.resize(rsaEncryptor.CiphertextLength(plaintext.length()));

            rsaEncryptor.Encrypt(rng, 
                reinterpret_cast<const byte*>(plaintext.data()), plaintext.length(),
                reinterpret_cast<byte*>(&ciphertext[0]),
                MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
            );
            finalOutput = ciphertext;
        } else {
            SecByteBlock aesKey(AES::MAX_KEYLENGTH);
            SecByteBlock iv(12);
            rng.GenerateBlock(aesKey, aesKey.size());
            rng.GenerateBlock(iv, iv.size());

            std::string aesCiphertext;
            GCM<AES>::Encryption gcm;
            gcm.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());
            if (!label.empty()) {
                gcm.SpecifyDataLengths(label.size(), plaintext.size(), 0);
                gcm.Update(reinterpret_cast<const byte*>(label.data()), label.size());
            }
            StringSource(plaintext, true, new AuthenticatedEncryptionFilter(gcm, new StringSink(aesCiphertext)));
            
            std::string actualCt = aesCiphertext.substr(0, aesCiphertext.length() - 16);
            std::string macTag = aesCiphertext.substr(aesCiphertext.length() - 16);

            std::string wrappedKey;
            StringSource(aesKey.data(), aesKey.size(), true, new PK_EncryptorFilter(rng, rsaEncryptor, new StringSink(wrappedKey)));

            std::string jsonHeader = "{\n  \"mode\": \"RSA-OAEP-AES-GCM\",\n  \"rsa_modulus\": " + std::to_string(pubKey.GetModulus().BitCount()) + ",\n";
            jsonHeader += "  \"hash\": \"SHA-256\",\n  \"wrapped_key\": \"" + Base64Encode(wrappedKey) + "\",\n";
            jsonHeader += "  \"iv\": \"" + Base64Encode(std::string(reinterpret_cast<const char*>(iv.data()), iv.size())) + "\",\n";
            jsonHeader += "  \"tag\": \"" + Base64Encode(macTag) + "\"\n}\n--PAYLOAD--\n";
            
            finalOutput = jsonHeader + actualCt;
        }

        if (outFormat == OutputFormat::TEXT) {
            finalOutput = Base64Encode(finalOutput);
        }
        WriteFileBinary(outFile, finalOutput);
    }

    static void DecryptData(InputMode inMode, const std::string& inValue, const std::string& privKeyPath, const std::string& outFile, OutputFormat inFormat, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privKey = LoadDecryptionKeyFromFile(privKeyPath);
        std::string ciphertext = LoadInput(inMode, inValue);

        if (inFormat == OutputFormat::TEXT) {
            ciphertext = Base64Decode(ciphertext);
        }

        size_t payloadPos = ciphertext.find("--PAYLOAD--\n");
        if (payloadPos != std::string::npos) {
            std::string header = ciphertext.substr(0, payloadPos);
            std::string actualCt = ciphertext.substr(payloadPos + 12);

            auto extractField = [&](const std::string& key) {
                size_t pos = header.find("\"" + key + "\": \"");
                if (pos == std::string::npos) throw std::runtime_error("Malformed JSON Header");
                pos += key.length() + 5;
                size_t end = header.find("\"", pos);
                return Base64Decode(header.substr(pos, end - pos));
            };

            std::string wrappedKey = extractField("wrapped_key");
            std::string iv = extractField("iv");
            std::string tag = extractField("tag");

            RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
            std::string aesKey;
            StringSource(wrappedKey, true, new PK_DecryptorFilter(rng, rsaDecryptor, new StringSink(aesKey)));

            GCM<AES>::Decryption gcm;
            gcm.SetKeyWithIV(reinterpret_cast<const byte*>(aesKey.data()), aesKey.size(), reinterpret_cast<const byte*>(iv.data()), iv.size());
            if (!label.empty()) {
                gcm.SpecifyDataLengths(label.size(), actualCt.size(), 0);
                gcm.Update(reinterpret_cast<const byte*>(label.data()), label.size());
            }

            std::string recovered;
            AuthenticatedDecryptionFilter df(gcm, new StringSink(recovered));
            df.Put(reinterpret_cast<const byte*>(actualCt.data()), actualCt.size());
            df.Put(reinterpret_cast<const byte*>(tag.data()), tag.size());
            df.MessageEnd();

            WriteFileBinary(outFile, recovered);
        } else {
            RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privKey);
            std::string recovered;
            recovered.resize(rsaDecryptor.MaxPlaintextLength(ciphertext.length()));

            DecodingResult result = rsaDecryptor.Decrypt(rng, 
                reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.length(),
                reinterpret_cast<byte*>(&recovered[0]),
                MakeParameters(Name::EncodingParameters(), ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()))
            );

            if (!result.isValidCoding) {
                throw std::runtime_error("Decryption failed: Label mismatch or corrupted ciphertext!");
            }
            
            recovered.resize(result.messageLength); 
            WriteFileBinary(outFile, recovered);
        }
    }
};

} // namespace

void PrintUsage(const char* prog) {
    std::cerr
        << "RSATOOL - Hybrid RSA-OAEP / AES-GCM Tool\n\n"
        << "Usage:\n"
        << "  " << prog << " keygen --bits <3072|4096> --pub <pub_file> --priv <priv_file>\n"
        << "  " << prog << " encrypt --in <file> --pub <pub_file> --out <file> [--label <text>]\n"
        << "  " << prog << " decrypt --in <file> --priv <priv_file> --out <file> [--label <text>]\n\n"
        << "Options:\n"
        << "  --pub <path>       RSA Public key file path.\n"
        << "  --priv <path>      RSA Private key file path.\n"
        << "  --text <string>    Input from command line string.\n"
        << "  --in <path>        Input from file.\n"
        << "  --out <path>       Output file path.\n"
        << "  --out-format       binary | text\n"
        << "  --in-format        binary | text\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    if (command == "--help" || command == "-h") {
        PrintUsage(argv[0]);
        return 0;
    }

    std::map<std::string, std::string> args;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.substr(0, 2) == "--" && i + 1 < argc) {
            args[arg] = argv[++i];
        }
    }

    try {
        if (command == "keygen") {
            uint32_t bits = args.count("--bits") ? std::stoul(args["--bits"]) : 3072;
            if (!args.count("--pub") || !args.count("--priv")) {
                throw std::invalid_argument("Missing --pub or --priv parameter.");
            }
            
            RSA_App::KeyGen(bits, args["--pub"], args["--priv"]);
            std::cout << "[+] Keygen successful.\n"
                      << "    Public Key : " << args["--pub"] << "\n"
                      << "    Private Key: " << args["--priv"] << "\n";
        } 
        else if (command == "encrypt") {
            if (!args.count("--pub")) throw std::invalid_argument("Missing --pub parameter.");
            if (!args.count("--out")) throw std::invalid_argument("Missing --out parameter.");

            bool hasText = args.count("--text");
            bool hasIn = args.count("--in");
            if (hasText == hasIn) {
                throw std::invalid_argument("Specify exactly one of --text or --in.");
            }

            InputMode inMode = hasText ? InputMode::TEXT : InputMode::FILE;
            std::string inValue = hasText ? args["--text"] : args["--in"];
            std::string label = args.count("--label") ? args["--label"] : "";

            OutputFormat fmt = OutputFormat::BINARY;
            std::string fmtArg = args.count("--out-format") ? args["--out-format"] : "";
            if (!fmtArg.empty() && !ParseOutputFormat(fmtArg, fmt)) {
                throw std::invalid_argument("Invalid format value. Use binary or text.");
            }

            RSA_App::EncryptData(inMode, inValue, args["--pub"], args["--out"], fmt, label);
            
            std::cout << "[+] Encryption successful.\n";
            std::cout << "    Key: " << args["--pub"] << "\n";
            std::cout << "    Output: " << args["--out"] << "\n";
        } 
        else if (command == "decrypt") {
            if (!args.count("--priv")) throw std::invalid_argument("Missing --priv parameter.");
            if (!args.count("--out")) throw std::invalid_argument("Missing --out parameter.");

            bool hasText = args.count("--text");
            bool hasIn = args.count("--in");
            if (hasText == hasIn) {
                throw std::invalid_argument("Specify exactly one of --text or --in.");
            }

            InputMode inMode = hasText ? InputMode::TEXT : InputMode::FILE;
            std::string inValue = hasText ? args["--text"] : args["--in"];
            std::string label = args.count("--label") ? args["--label"] : "";

            OutputFormat fmt = OutputFormat::BINARY;
            std::string fmtArg = args.count("--in-format") ? args["--in-format"] : "";
            if (!fmtArg.empty() && !ParseOutputFormat(fmtArg, fmt)) {
                throw std::invalid_argument("Invalid format value. Use binary or text.");
            }

            RSA_App::DecryptData(inMode, inValue, args["--priv"], args["--out"], fmt, label);
            
            std::cout << "[+] Decryption successful.\n";
            std::cout << "    Key: " << args["--priv"] << "\n";
            std::cout << "    Output: " << args["--out"] << "\n";
        }
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}