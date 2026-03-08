#include "wrapper.h"
// #include "aes.h"  // tymczasowo wyłączone

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
    long inSize = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);

    std::vector<uint8_t> inBuf(inSize);
    fread(inBuf.data(), 1, inSize, fIn);
    fclose(fIn);

    SizeT outBufSize = (SizeT)(inSize + inSize / 3 + 128);
    std::vector<uint8_t> comp(outBufSize);
    SizeT compSize = outBufSize;

    uint8_t props[5];
    SizeT propsSize = 5;

    int res = LzmaCompress(
        comp.data(), &compSize,
        inBuf.data(), (SizeT)inSize,
        props, &propsSize,
        5, 0, 3, 0, 2, 32, 1
    );

    if (res != SZ_OK) return 2;

    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 3;

    fwrite("PBCRYPT1", 1, 8, fOut);

    uint8_t saltLen = 0;
    fwrite(&saltLen, 1, 1, fOut);

    uint8_t ivLen = 0; // brak IV, brak AES
    fwrite(&ivLen, 1, 1, fOut);

    uint8_t propsLen = (uint8_t)propsSize;
    fwrite(&propsLen, 1, 1, fOut);
    fwrite(props, 1, propsSize, fOut);

    uint64_t csize = compSize;
    fwrite(&csize, 1, 8, fOut);

    fwrite(comp.data(), 1, compSize, fOut);

    fclose(fOut);
    return 0;
}

int __stdcall DecryptAndDecompress(const char* inFile,
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
    if (ivLen != 0) { // w tej wersji nie używamy IV
        fclose(fIn);
        return 3;
    }

    uint8_t propsLen = 0;
    fread(&propsLen, 1, 1, fIn);
    if (propsLen != 5) {
        fclose(fIn);
        return 4;
    }

    uint8_t props[5];
    fread(props, 1, 5, fIn);

    uint64_t encSize64 = 0;
    fread(&encSize64, 1, 8, fIn);

    SizeT encSize = (SizeT)encSize64;

    std::vector<uint8_t> enc(encSize);
    fread(enc.data(), 1, encSize, fIn);
    fclose(fIn);

    SizeT outSize = encSize * 50 + 1024;
    std::vector<uint8_t> out(outSize);
    SizeT outProcessed = outSize;

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
