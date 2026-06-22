#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <stdexcept>

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>

using namespace CryptoPP;
using namespace std;

void PrintUsage(const char* prog) {
    cerr << "RSATOOL - Hybrid RSA-OAEP / AES-GCM Tool\n\n"
         << "Usage:\n"
         << "  " << prog << " keygen --bits <3072|4096> --pub <pub_file> --priv <priv_file>\n"
         << "  " << prog << " encrypt --in <file> --pub <pub_file> --out <file>\n"
         << "  " << prog << " decrypt --in <file> --priv <priv_file> --out <file>\n";
}

map<string, string> ParseArgs(int argc, char* argv[]) {
    map<string, string> args;
    for (int i = 2; i < argc; i++) {
        string arg = argv[i];
        if (arg.substr(0, 2) == "--" && i + 1 < argc) {
            args[arg] = argv[i + 1];
            i++;
        }
    }
    return args;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    string command = argv[1];
    auto args = ParseArgs(argc, argv);

    try {
        if (command == "keygen") {
            if (!args.count("--bits") || !args.count("--pub") || !args.count("--priv")) {
                cerr << "[-] Error: Missing arguments for keygen.\n";
                return 1;
            }

            int bits = stoi(args["--bits"]);
            string pubPath = args["--pub"];
            string privPath = args["--priv"];

            AutoSeededRandomPool prng;
            RSA::PrivateKey privateKey;
            privateKey.Initialize(prng, bits);
            RSA::PublicKey publicKey(privateKey);

            // Ghi Private Key mã hóa Base64
            if (privPath == "stdout") {
                cout << "--- BEGIN RSA PRIVATE KEY ---\n";
                Base64Encoder encoder(new FileSink(cout));
                privateKey.DEREncode(encoder);
                encoder.MessageEnd();
                cout << "\n--- END RSA PRIVATE KEY ---\n";
            } else {
                Base64Encoder encoder(new FileSink(privPath.c_str()));
                privateKey.DEREncode(encoder);
                encoder.MessageEnd();
                cerr << "[+] Private key saved to: " << privPath << "\n";
            }

            // Ghi Public Key mã hóa Base64
            if (pubPath == "stdout") {
                cout << "--- BEGIN RSA PUBLIC KEY ---\n";
                Base64Encoder encoder(new FileSink(cout));
                publicKey.DEREncode(encoder);
                encoder.MessageEnd();
                cout << "\n--- END RSA PUBLIC KEY ---\n";
            } else {
                Base64Encoder encoder(new FileSink(pubPath.c_str()));
                publicKey.DEREncode(encoder);
                encoder.MessageEnd();
                cerr << "[+] Public key saved to: " << pubPath << "\n";
            }
        }
        else if (command == "encrypt") {
            if (!args.count("--in") || !args.count("--pub") || !args.count("--out")) {
                cerr << "[-] Error: Missing arguments for encrypt.\n";
                return 1;
            }

            AutoSeededRandomPool prng;
            RSA::PublicKey publicKey;

            // Đọc Public Key từ file Base64
            FileSource pubFile(args["--pub"].c_str(), true, new Base64Decoder);
            publicKey.BERDecode(pubFile);

            // Đọc dữ liệu Plaintext đầu vào
            string plaintext;
            FileSource(args["--in"].c_str(), true, new StringSink(plaintext));

            // 1. Sinh ngẫu nhiên Session Key (AES 16 bytes) và IV (12 bytes cho GCM)
            SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
            SecByteBlock aesIv(12);
            prng.GenerateBlock(aesKey, aesKey.size());
            prng.GenerateBlock(aesIv, aesIv.size());

            // 2. Mã hóa dữ liệu bằng AES-GCM với Session Key vừa sinh
            string ciphertext;
            GCM<AES>::Encryption aesEnc;
            aesEnc.SetKeyWithIV(aesKey, aesKey.size(), aesIv, aesIv.size());
            StringSource(plaintext, true, new AuthenticatedEncryptionFilter(aesEnc, new StringSink(ciphertext)));

            // 3. Dùng RSA-OAEP mã hóa chiếc AES Key (ĐÃ XÓA DÒNG DECRYPTOR LỖI)
            string encryptedKey;
            RSAES_OAEP_SHA256_Encryptor rsaEnc(publicKey);
            StringSource(aesKey, aesKey.size(), true, new PK_EncryptorFilter(prng, rsaEnc, new StringSink(encryptedKey)));

            // 4. Đóng gói file lai: [Độ dài RSA Key (4 bytes)] + [RSA Encrypted Key] + [IV (12 bytes)] + [Ciphertext GCM]
            ofstream outFile(args["--out"].c_str(), ios::binary);
            uint32_t keyLen = encryptedKey.size();
            outFile.write(reinterpret_cast<const char*>(&keyLen), sizeof(keyLen));
            outFile.write(encryptedKey.data(), encryptedKey.size());
            outFile.write(reinterpret_cast<const char*>(aesIv.data()), aesIv.size());
            outFile.write(ciphertext.data(), ciphertext.size());

            cerr << "[+] Hybrid Encryption completed successfully.\n";
        }
        else if (command == "decrypt") {
            if (!args.count("--in") || !args.count("--priv") || !args.count("--out")) {
                cerr << "[-] Error: Missing arguments for decrypt.\n";
                return 1;
            }

            AutoSeededRandomPool prng;
            RSA::PrivateKey privateKey;

            // Đọc Private Key từ file Base64
            FileSource privFile(args["--priv"].c_str(), true, new Base64Decoder);
            privateKey.BERDecode(privFile);

            // Bóc tách file lai mã hóa cấu trúc nhị phân
            ifstream inFile(args["--in"].c_str(), ios::binary);
            if (!inFile) throw runtime_error("Cannot open encrypted file.");

            uint32_t keyLen = 0;
            inFile.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));

            string encryptedKey(keyLen, 0);
            inFile.read(&encryptedKey[0], keyLen);

            SecByteBlock aesIv(12);
            inFile.read(reinterpret_cast<char*>(aesIv.data()), aesIv.size());

            string ciphertext((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());

            // 1. Dùng RSA hốt lại chiếc AES Session Key
            string decryptedKey;
            RSAES_OAEP_SHA256_Decryptor rsaDec(privateKey);
            StringSource(encryptedKey, true, new PK_DecryptorFilter(prng, rsaDec, new StringSink(decryptedKey)));

            // 2. Dùng chiếc AES Session Key bẻ khóa file dữ liệu qua GCM
            string decryptedText;
            GCM<AES>::Decryption aesDec;
            aesDec.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(decryptedKey.data()), decryptedKey.size(), aesIv, aesIv.size());
            StringSource(ciphertext, true, new AuthenticatedDecryptionFilter(aesDec, new StringSink(decryptedText)));

            // 3. Ghi file Plaintext hoàn chỉnh
            ofstream outFile(args["--out"].c_str());
            outFile << decryptedText;

            cerr << "[+] Hybrid Decryption completed successfully.\n";
        }
    } catch (const Exception& e) {
        cerr << "[-] Crypto++ Error: " << e.what() << "\n";
        return 1;
    } catch (const exception& e) {
        cerr << "[-] Standard Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}