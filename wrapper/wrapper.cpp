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
//  Prosty SHA256 placeholder (32 bajty z hasła)
// ------------------------------------------------------------
static void sha256_simple(const char* password, uint8_t out[32]) {
    memset(out, 0, 32);
    size_t len = strlen(password);
    for (size_t i = 0; i < len && i < 32; i++)
        out[i] = (uint8_t)password[i];
}

// ------------------------------------------------------------
//  AES + LZMA: ENCRYPT
// ------------------------------------------------------------
int __stdcall EncryptAndCompress(const char* inFile,
                                 const char* outFile,
                                 const char* password)
{
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

    // --- LZMA compress ---
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

    // --- AES key ---
    uint8_t key[32];
    sha256_simple(password, key);
    aes256_init(key);

    // --- IV ---
    uint8_t iv[16];
    for (int i = 0; i < 16; i++)
        iv[i] = (uint8_t)(rand() & 0xFF);

    // --- PKCS#7 padding ---
    uint8_t pad = 16 - (compSize % 16);
    if (pad == 0) pad = 16;

    SizeT padded = compSize + pad;
    comp.resize(padded);

    for (int i = 0; i < pad; i++)
        comp[compSize + i] = pad;

    // --- AES CBC encrypt ---
    aes256_cbc_encrypt(comp.data(), padded, iv);

    // --- Zapis pliku ---
    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 3;

    // magic
    fwrite("PBCRYPT1", 1, 8, fOut);

    // brak soli
    uint8_t saltLen = 0;
    fwrite(&saltLen, 1, 1, fOut);

    // IV
    uint8_t ivLen = 16;
    fwrite(&ivLen, 1, 1, fOut);
    fwrite(iv, 1, 16, fOut);

    // props
    uint8_t propsLen = (uint8_t)propsSize;
    fwrite(&propsLen, 1, 1, fOut);
    fwrite(props, 1, propsSize, fOut);

    // oryginalny rozmiar
    uint64_t origSize64 = (uint64_t)inSize;
    fwrite(&origSize64, 1, 8, fOut);

    // rozmiar zaszyfrowany
    uint64_t encSize64 = (uint64_t)padded;
    fwrite(&encSize64, 1, 8, fOut);

    // dane
    fwrite(comp.data(), 1, padded, fOut);

    fclose(fOut);
    return 0;
}

// ------------------------------------------------------------
//  AES + LZMA: DECRYPT
// ------------------------------------------------------------
int __stdcall DecryptAndDecompress(const char* inFile,
                                   const char* outFile,
                                   const char* password)
{
    FILE* fIn = fopen(inFile, "rb");
    if (!fIn) return 1;

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
    fread(enc.data(), 1, encSize, fIn);
    fclose(fIn);

    // --- AES key ---
    uint8_t key[32];
    sha256_simple(password, key);
    aes256_init(key);

    // --- AES CBC decrypt ---
    aes256_cbc_decrypt(enc.data(), encSize, iv);

    // --- PKCS#7 unpadding ---
    uint8_t pad = enc[encSize - 1];
    if (pad == 0 || pad > 16) return 7;
    encSize -= pad;

    // --- LZMA decompress ---
    std::vector<uint8_t> out(origSize);
    SizeT outProcessed = origSize;

    int res = LzmaUncompress(
        out.data(), &outProcessed,
        enc.data(), &encSize,
        props, 5
    );

    if (res != SZ_OK) return 5;

    // --- zapis pliku wynikowego ---
    FILE* fOut = fopen(outFile, "wb");
    if (!fOut) return 6;

    fwrite(out.data(), 1, outProcessed, fOut);
    fclose(fOut);

    return 0;
}
