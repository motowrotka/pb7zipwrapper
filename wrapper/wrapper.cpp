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

int DecryptAndDecompress(const char* inFile,
                         const char* outFolder,
                         const char* password)
{
    (void)inFile;
    (void)outFolder;
    (void)password;
    return -1; // na razie niezaimplementowane
}
