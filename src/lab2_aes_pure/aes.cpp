#include "aes.h"
#include <cstring>
#include <cstdlib>

#ifdef __x86_64__
#include <wmmintrin.h>
#endif

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

AES::AES(const uint8_t* key, size_t keyLen, const uint8_t* iv) {
    if (keyLen == 16) numRounds = 10;
    else if (keyLen == 24) numRounds = 12;
    else if (keyLen == 32) numRounds = 14;
    else exit(1); 

    KeyExpansion(key, keyLen);
    std::memcpy(counter, iv, 16);
}

void AES::KeyExpansion(const uint8_t* key, size_t keyLen) {
    int Nk = keyLen / 4; 
    std::memcpy(roundKeys, key, keyLen);
    
    int bytesGenerated = keyLen;
    int rconIteration = 1;
    uint8_t temp[4];

    while (bytesGenerated < (numRounds + 1) * 16) {
        for (int i = 0; i < 4; i++) temp[i] = roundKeys[i + bytesGenerated - 4];
        
        if (bytesGenerated % (Nk * 4) == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[rconIteration - 1];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
            rconIteration++;
        } 
        else if (Nk > 6 && (bytesGenerated % (Nk * 4)) == 16) {
            for (int i = 0; i < 4; i++) temp[i] = sbox[temp[i]];
        }
        
        for (uint8_t i = 0; i < 4; i++) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - (Nk * 4)] ^ temp[i];
            bytesGenerated++;
        }
    }
}

void AES::AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

void AES::SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

void AES::ShiftRows(uint8_t* state) {
    uint8_t temp;
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

void AES::MixColumns(uint8_t* state) {
    uint8_t tmp[16];
    for (int i = 0; i < 4; i++) {
        uint8_t* col = state + i * 4;
        tmp[i * 4 + 0] = gf_mul(0x02, col[0]) ^ gf_mul(0x03, col[1]) ^ col[2] ^ col[3];
        tmp[i * 4 + 1] = col[0] ^ gf_mul(0x02, col[1]) ^ gf_mul(0x03, col[2]) ^ col[3];
        tmp[i * 4 + 2] = col[0] ^ col[1] ^ gf_mul(0x02, col[2]) ^ gf_mul(0x03, col[3]);
        tmp[i * 4 + 3] = gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ gf_mul(0x02, col[3]);
    }
    std::memcpy(state, tmp, 16);
}

void AES::EncryptBlock(const uint8_t* in, uint8_t* out) {
    uint8_t state[16];
    
    std::memcpy(state, in, 16);

    AddRoundKey(state, roundKeys);
    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);

    std::memcpy(out, state, 16);
}

void AES::IncrementCounter() {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

void AES::ProcessData(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
    output.resize(input.size());
    uint8_t keystreamBlock[16];
    size_t length = input.size();
    size_t offset = 0;

    while (length > 0) {
        // EncryptBlock(counter, keystreamBlock);
        EncryptBlock_NI(counter, keystreamBlock);
        IncrementCounter();

        size_t bytesToProcess = (length < 16) ? length : 16;
        for (size_t i = 0; i < bytesToProcess; ++i) {
            output[offset + i] = input[offset + i] ^ keystreamBlock[i];
        }
        offset += bytesToProcess;
        length -= bytesToProcess;
    }
}

void AES::MultiplyByX(uint8_t* block) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t next_carry = (block[i] >> 7) & 1;
        block[i] = (block[i] << 1) | carry;
        carry = next_carry;
    }
    if (carry) block[0] ^= 0x87; 
}

void AES::ProcessXTS(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const uint8_t* key2, const uint8_t* tweak) {
    output.resize(input.size());
    
    AES aes_tweak(key2, 16, counter); 
    uint8_t T[16];
    aes_tweak.EncryptBlock(tweak, T);

    size_t length = input.size();
    size_t offset = 0;

    while (length >= 16) {
        uint8_t block[16];
        for (int i = 0; i < 16; i++) block[i] = input[offset + i] ^ T[i];
        EncryptBlock(block, block);
        for (int i = 0; i < 16; i++) output[offset + i] = block[i] ^ T[i];

        MultiplyByX(T); 
        offset += 16;
        length -= 16;
    }
}

void AES::EncryptBlock_NI(const uint8_t* in, uint8_t* out) {
#ifdef __x86_64__
    __m128i m = _mm_loadu_si128((__m128i*)in);
    
    m = _mm_xor_si128(m, _mm_loadu_si128((__m128i*)&roundKeys[0]));
    
    for (int i = 1; i < numRounds; i++) {
        m = _mm_aesenc_si128(m, _mm_loadu_si128((__m128i*)&roundKeys[i * 16]));
    }
    
    m = _mm_aesenclast_si128(m, _mm_loadu_si128((__m128i*)&roundKeys[numRounds * 16]));
    
    _mm_storeu_si128((__m128i*)out, m);
#else
    EncryptBlock(in, out);
#endif
}

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

void AES::InvSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) state[i] = rsbox[state[i]];
}

void AES::InvShiftRows(uint8_t* state) {
    uint8_t temp;
    temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
    temp = state[10]; state[10] = state[2]; state[2] = temp;
    temp = state[14]; state[14] = state[6]; state[6] = temp;
    temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
}

void AES::InvMixColumns(uint8_t* state) {
    uint8_t tmp[16];
    for (int i = 0; i < 4; i++) {
        uint8_t* col = state + i * 4;
        tmp[i * 4 + 0] = gf_mul(0x0e, col[0]) ^ gf_mul(0x0b, col[1]) ^ gf_mul(0x0d, col[2]) ^ gf_mul(0x09, col[3]);
        tmp[i * 4 + 1] = gf_mul(0x09, col[0]) ^ gf_mul(0x0e, col[1]) ^ gf_mul(0x0b, col[2]) ^ gf_mul(0x0d, col[3]);
        tmp[i * 4 + 2] = gf_mul(0x0d, col[0]) ^ gf_mul(0x09, col[1]) ^ gf_mul(0x0e, col[2]) ^ gf_mul(0x0b, col[3]);
        tmp[i * 4 + 3] = gf_mul(0x0b, col[0]) ^ gf_mul(0x0d, col[1]) ^ gf_mul(0x09, col[2]) ^ gf_mul(0x0e, col[3]);
    }
    std::memcpy(state, tmp, 16);
}

void AES::DecryptBlock(const uint8_t* in, uint8_t* out) {
    uint8_t state[16];
    std::memcpy(state, in, 16);

    AddRoundKey(state, roundKeys + numRounds * 16);
    for (int round = numRounds - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    std::memcpy(out, state, 16);
}

void AES::DecryptXTS(const std::vector<uint8_t>& input, std::vector<uint8_t>& output, const uint8_t* key2, const uint8_t* tweak) {
    output.resize(input.size());
    
    AES aes_tweak(key2, 16, counter); 
    uint8_t T[16];
    aes_tweak.EncryptBlock(tweak, T);

    size_t length = input.size();
    size_t offset = 0;

    while (length >= 16) {
        uint8_t block[16];
        for (int i = 0; i < 16; i++) block[i] = input[offset + i] ^ T[i];
        DecryptBlock(block, block);
        for (int i = 0; i < 16; i++) output[offset + i] = block[i] ^ T[i];

        MultiplyByX(T); 
        offset += 16;
        length -= 16;
    }
}