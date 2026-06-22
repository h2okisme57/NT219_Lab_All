#ifndef AES_H
#define AES_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

class AES {
    friend void RunKAT(const std::string& filename);

private:
    uint8_t roundKeys[240]; 
    uint8_t counter[16];
    int numRounds;          

    void KeyExpansion(const uint8_t* key, size_t keyLen);
    void SubBytes(uint8_t* state);
    void ShiftRows(uint8_t* state);
    void MixColumns(uint8_t* state);
    void AddRoundKey(uint8_t* state, const uint8_t* roundKey);
    void EncryptBlock(const uint8_t* in, uint8_t* out);
    void IncrementCounter();
    void MultiplyByX(uint8_t* block);
    void EncryptBlock_NI(const uint8_t* in, uint8_t* out);
    void InvSubBytes(uint8_t* state);
    void InvShiftRows(uint8_t* state);
    void InvMixColumns(uint8_t* state);
    void DecryptBlock(const uint8_t* in, uint8_t* out);

public:
    explicit AES(const uint8_t* key, size_t keyLen, const uint8_t* iv);
    void ProcessData(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
    void ProcessXTS(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const uint8_t* key2, const uint8_t* tweak);
    void DecryptXTS(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const uint8_t* key2, const uint8_t* tweak);
};

#endif