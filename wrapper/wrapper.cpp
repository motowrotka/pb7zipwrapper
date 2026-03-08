#include "wrapper.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <stdint.h>

extern "C" {
#include "LzmaLib.h"
}

static void sha256_simple(const char* password, uint8_t out[32]) {
    memset(out, 0, 32);
    size_t len = strlen(password);
    for (size_t i = 0; i < len && i < 32; i++)
        out[i] = (uint8_t)password[i];
}

// --- MINIMALNY TEST AES-256 (lokalny, niezależny od aes.c) ---

static const uint8_t test_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t test_Rcon[15] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D
};

static void test_KeyExpansion(const uint8_t key[32], uint8_t rk[240]) {
    memcpy(rk, key, 32);

    uint8_t temp[4];
    int bytesGenerated = 32;
    int rconIter = 1;

    while (bytesGenerated < 240) {
        memcpy(temp, &rk[bytesGenerated - 4], 4);

        if (bytesGenerated % 32 == 0) {
            uint8_t t = temp[0];
            temp[0] = test_sbox[temp[1]];
            temp[1] = test_sbox[temp[2]];
            temp[2] = test_sbox[temp[3]];
            temp[3] = test_sbox[t];
            temp[0] ^= test_Rcon[rconIter++];
        }

        for (int i = 0; i < 4; i++) {
            rk[bytesGenerated] = rk[bytesGenerated - 32] ^ temp[i];
            bytesGenerated++;
        }
    }
}

static void test_AddRoundKey(uint8_t* state, int round, const uint8_t rk[240]) {
    for (int i = 0; i < 16; i++)
        state[i] ^= rk[round * 16 + i];
}

static void test_SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++)
        state[i] = test_sbox[state[i]];
}

static void test_ShiftRows(uint8_t* state) {
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static uint8_t test_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

static void test_MixColumns(uint8_t* s) {
    for (int i = 0; i < 16; i += 4) {
        uint8_t a = s[i];
        uint8_t b = s[i+1];
        uint8_t c = s[i+2];
        uint8_t d = s[i+3];

        uint8_t e = a ^ b ^ c ^ d;

        uint8_t xa = test_xtime(a ^ b);
        uint8_t xb = test_xtime(b ^ c);
        uint8_t xc = test_xtime(c ^ d);
        uint8_t xd = test_xtime(d ^ a);

        s[i]   ^= e ^ xa;
        s[i+1] ^= e ^ xb;
        s[i+2] ^= e ^ xc;
        s[i+3] ^= e ^ xd;
    }
}

static void test_aes256_encrypt_block(uint8_t block[16], const uint8_t rk[240]) {
    test_AddRoundKey(block, 0, rk);

    for (int round = 1; round <= 13; round++) {
        test_SubBytes(block);
        test_ShiftRows(block);
        test_MixColumns(block);
        test_AddRoundKey(block, round, rk);
    }

    test_SubBytes(block);
    test_ShiftRows(block);
    test_AddRoundKey(block, 14, rk);
}

static int local_aes256_selftest() {
    const uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    uint8_t plain[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    const uint8_t expected[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
        0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };

    uint8_t rk[240];
    test_KeyExpansion(key, rk);

    uint8_t block[16];
    memcpy(block, plain, 16);

    test_aes256_encrypt_block(block, rk);

    return memcmp(block, expected, 16) == 0 ? 1 : 0;
}



int __stdcall EncryptAndCompress(const char* inFile,
                                 const char* outFile,
                                 const char* password)
{
    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

    fseek(fIn, 0, SEEK_END);
    long inSizeLong = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);
    if (inSizeLong < 0) { fclose(fIn); return 1; }

    SizeT inSize = (SizeT)inSizeLong;

    std::vector<uint8_t> inBuf(inSize);
    if (fread(inBuf.data(), 1, inSize, fIn) != inSize) {
        fclose(fIn);
        return 1;
    }
    fclose(fIn);

    // LZMA compress
    SizeT outBufSize = inSize + inSize / 3 + 128;
    std::vector<uint8_t> comp(outBufSize);
    SizeT compSize = outBufSize;

    uint8_t props[5];
    SizeT propsSize = 5;

    int res = LzmaCompress(
        comp.data(), &compSize,
        inBuf.data(), inSize,
        props, &propsSize,
        5, 0, 3, 0, 2, 32, 1
    );
    if (res != SZ_OK) return 2;

    // AES key
    uint8_t key[32];
    sha256_simple(password, key);
    aes256_init(key);

    // IV
    uint8_t iv[16];
    for (int i = 0; i < 16; i++)
        iv[i] = (uint8_t)(rand() & 0xFF);

    // zero padding do pełnego bloku 16
    SizeT padded = compSize;
    if (padded % 16 != 0) {
        SizeT extra = 16 - (padded % 16);
        padded += extra;
    }
    comp.resize(padded, 0);

    // AES CBC encrypt
    aes256_cbc_encrypt(comp.data(), padded, iv);

    // zapis pliku
    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 3;

    fwrite("PBCRYPT1", 1, 8, fOut);

    uint8_t saltLen = 0;
    fwrite(&saltLen, 1, 1, fOut);

    uint8_t ivLen = 16;
    fwrite(&ivLen, 1, 1, fOut);
    fwrite(iv, 1, 16, fOut);

    uint8_t propsLen = (uint8_t)propsSize;
    fwrite(&propsLen, 1, 1, fOut);
    fwrite(props, 1, propsSize, fOut);

    uint64_t origSize64 = (uint64_t)inSize;
    fwrite(&origSize64, 1, 8, fOut);

    uint64_t encSize64 = (uint64_t)padded;
    fwrite(&encSize64, 1, 8, fOut);

    fwrite(comp.data(), 1, padded, fOut);

    fclose(fOut);
    return 0;
}

int __stdcall DecryptAndDecompress(const char* inFile,
                                   const char* outFile,
                                   const char* password)
{
    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

    if (!local_aes256_selftest()) {
    fclose(fIn);
    return 9;
    }



    char magic[8];
    if (fread(magic, 1, 8, fIn) != 8) {
        fclose(fIn);
        return 1;
    }
    if (memcmp(magic, "PBCRYPT1", 8) != 0) {
        fclose(fIn);
        return 2;
    }

    uint8_t saltLen = 0;
    fread(&saltLen, 1, 1, fIn);

    uint8_t ivLen = 0;
    fread(&ivLen, 1, 1, fIn);
    if (ivLen != 16) {
        fclose(fIn);
        return 3;
    }

    uint8_t iv[16];
    fread(iv, 1, 16, fIn);

    uint8_t propsLen = 0;
    fread(&propsLen, 1, 1, fIn);
    if (propsLen != 5) {
        fclose(fIn);
        return 4;
    }

    uint8_t props[5];
    fread(props, 1, 5, fIn);

    uint64_t origSize64 = 0;
    fread(&origSize64, 1, 8, fIn);

    uint64_t encSize64 = 0;
    fread(&encSize64, 1, 8, fIn);

    SizeT origSize = (SizeT)origSize64;
    SizeT encSize  = (SizeT)encSize64;

    std::vector<uint8_t> enc(encSize);
    if (fread(enc.data(), 1, encSize, fIn) != encSize) {
        fclose(fIn);
        return 1;
    }
    fclose(fIn);

    // AES key
    uint8_t key[32];
    sha256_simple(password, key);
    aes256_init(key);

    // AES CBC decrypt
    aes256_cbc_decrypt(enc.data(), encSize, iv);

    // LZMA decompress – używamy całego encSize po decrypt
    std::vector<uint8_t> out(origSize);
    SizeT outProcessed = origSize;
    SizeT srcLen = encSize;

    int res = LzmaUncompress(
        out.data(), &outProcessed,
        enc.data(), &srcLen,
        props, 5
    );
    if (res != SZ_OK) return 5;

    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 6;

    fwrite(out.data(), 1, outProcessed, fOut);
    fclose(fOut);

    return 0;
}
