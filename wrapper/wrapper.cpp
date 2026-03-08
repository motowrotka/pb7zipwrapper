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

static void sha256_simple(const char* password, uint8_t out[32]) {
    memset(out, 0, 32);
    size_t len = strlen(password);
    for (size_t i = 0; i < len && i < 32; i++)
        out[i] = (uint8_t)password[i];
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

    if (!aes256_selftest()) {
    // AES jest uszkodzony / niezgodny z tym, co zakładamy
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
