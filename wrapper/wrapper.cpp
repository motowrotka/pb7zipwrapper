#include "wrapper.h"
#include "aes.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <stdint.h>

extern "C" {
#include "LzmaLib.h"
}

// ------------------------------------------------------------
//  PROSTE SHA-256 (placeholder dla opcji A)
// ------------------------------------------------------------
static void sha256_simple(const char* password, uint8_t out[32]) {
    memset(out, 0, 32);
    size_t len = strlen(password);
    for (size_t i = 0; i < len && i < 32; i++)
        out[i] = (uint8_t)password[i];
}

// ------------------------------------------------------------
//  ENCRYPT + COMPRESS
// ------------------------------------------------------------
int EncryptAndCompress(const char* inFile,
                       const char* outFile,
                       const char* password)
{
    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

    fseek(fIn, 0, SEEK_END);
    long inSize = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);

    std::vector<uint8_t> inBuf(inSize);
    fread(inBuf.data(), 1, inSize, fIn);
    fclose(fIn);

    size_t outBufSize = inSize + inSize/3 + 128;
    std::vector<uint8_t> comp(outBufSize);
    size_t compSize = outBufSize;

    uint8_t props[5];
    size_t propsSize = 5;

    int res = LzmaCompress(
        comp.data(), &compSize,
        inBuf.data(), inSize,
        props, &propsSize,
        5, 0, 3, 0, 2, 32, 1
    );

    if (res != SZ_OK) return 2;

    uint8_t key[32];
    sha256_simple(password, key);
    aes256_init(key);

    uint8_t iv[16];
    for (int i = 0; i < 16; i++)
        iv[i] = (uint8_t)(rand() & 0xFF);

    size_t padded = compSize;
    if (padded % 16 != 0)
        padded += 16 - (padded % 16);

    comp.resize(padded, 0);

    aes256_cbc_encrypt(comp.data(), padded, iv);

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

    uint64_t csize = padded;
    fwrite(&csize, 1, 8, fOut);

    fwrite(comp.data(), 1, padded, fOut);

    fclose(fOut);
    return 0;
}

// ------------------------------------------------------------
//  CBC DECRYPT
// ------------------------------------------------------------
static void aes256_cbc_decrypt_full(uint8_t* data, size_t len, const uint8_t* iv) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t i = 0; i < len; i += 16) {
        uint8_t block[16];
        memcpy(block, &data[i], 16);

        aes256_decrypt_block(&data[i]);

        for (int j = 0; j < 16; j++)
            data[i+j] ^= prev[j];

        memcpy(prev, block, 16);
    }
}

// ------------------------------------------------------------
//  DECRYPT + DECOMPRESS
// ------------------------------------------------------------
int DecryptAndDecompress(const char* inFile,
                         const char* outFolder,
                         const char* password)
{
    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

    char magic[8];
    fread(magic, 1, 8, fIn);
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

    uint64_t encSize = 0;
    fread(&encSize, 1, 8, fIn);

    std::vector<uint8_t> enc(encSize);
    fread(enc.data(), 1, encSize, fIn);
    fclose(fIn);

    uint8_t key[32];
    sha256_simple(password, key);
    aes256_init(key);

    aes256_cbc_decrypt_full(enc.data(), encSize, iv);

    size_t outSize = encSize * 20;
    std::vector<uint8_t> out(outSize);

    size_t outProcessed = outSize;

    int res = LzmaUncompress(
        out.data(), &outProcessed,
        enc.data(), &encSize,
        props, 5
    );

    if (res != SZ_OK) return 5;

    std::string outPath = std::string(outFolder) + "/output.bin";

    FILE* fOut = fopen(outPath.c_str(), "wb");
    if (!fOut) return 6;

    fwrite(out.data(), 1, outProcessed, fOut);
    fclose(fOut);

    return 0;
}
