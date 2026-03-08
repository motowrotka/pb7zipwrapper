#include "wrapper.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <stdint.h>

extern "C" {
#include "LzmaLib.h"
}

// ENCRYPT + COMPRESS (tu: tylko LZMA, bez AES)
int __stdcall EncryptAndCompress(const char* inFile,
                                 const char* outFile,
                                 const char* password)
{
    (void)password; // na razie ignorujemy hasło

    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

    fseek(fIn, 0, SEEK_END);
    long inSizeLong = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);
    if (inSizeLong < 0) {
        fclose(fIn);
        return 1;
    }

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

    // zapis pliku: prosty nagłówek + dane LZMA
    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 3;

    // magic
    fwrite("PBCRYPT0", 1, 8, fOut);

    // props length + props
    uint8_t propsLen = (uint8_t)propsSize;
    fwrite(&propsLen, 1, 1, fOut);
    fwrite(props, 1, propsSize, fOut);

    // oryginalny rozmiar
    uint64_t origSize64 = (uint64_t)inSize;
    fwrite(&origSize64, 1, 8, fOut);

    // rozmiar skompresowany
    uint64_t compSize64 = (uint64_t)compSize;
    fwrite(&compSize64, 1, 8, fOut);

    // dane LZMA
    fwrite(comp.data(), 1, compSize, fOut);

    fclose(fOut);
    return 0;
}

// DECRYPT + DECOMPRESS (tu: tylko LZMA, bez AES)
int __stdcall DecryptAndDecompress(const char* inFile,
                                   const char* outFile,
                                   const char* password)
{
    (void)password; // na razie ignorujemy hasło

    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

    char magic[8];
    if (fread(magic, 1, 8, fIn) != 8) {
        fclose(fIn);
        return 1;
    }
    if (memcmp(magic, "PBCRYPT0", 8) != 0) {
        fclose(fIn);
        return 2;
    }

    uint8_t propsLen = 0;
    if (fread(&propsLen, 1, 1, fIn) != 1) {
        fclose(fIn);
        return 1;
    }
    if (propsLen != 5) {
        fclose(fIn);
        return 4;
    }

    uint8_t props[5];
    if (fread(props, 1, 5, fIn) != 5) {
        fclose(fIn);
        return 1;
    }

    uint64_t origSize64 = 0;
    if (fread(&origSize64, 1, 8, fIn) != 8) {
        fclose(fIn);
        return 1;
    }

    uint64_t compSize64 = 0;
    if (fread(&compSize64, 1, 8, fIn) != 8) {
        fclose(fIn);
        return 1;
    }

    SizeT origSize = (SizeT)origSize64;
    SizeT compSize = (SizeT)compSize64;

    std::vector<uint8_t> comp(compSize);
    if (fread(comp.data(), 1, compSize, fIn) != compSize) {
        fclose(fIn);
        return 1;
    }
    fclose(fIn);

    std::vector<uint8_t> out(origSize);
    SizeT outProcessed = origSize;
    SizeT srcLen = compSize;

    int res = LzmaUncompress(
        out.data(), &outProcessed,
        comp.data(), &srcLen,
        props, 5
    );
    if (res != SZ_OK) return 5;

    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 6;

    fwrite(out.data(), 1, outProcessed, fOut);
    fclose(fOut);

    return 0;
}
