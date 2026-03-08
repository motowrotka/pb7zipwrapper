#include <cstdio>
#include <vector>
#include <string>

extern "C" {
#include "LzmaLib.h"
}

extern "C" {

__declspec(dllexport)
int EncryptAndCompress(const char* inFile,
                       const char* outFile,
                       const char* password)
{
    // Na razie ignorujemy password – najpierw ogarniemy samą kompresję.
    // 1. Wczytaj plik wejściowy
    FILE* fIn = std::fopen(inFile, "rb");
    if (!fIn) return 1;

    std::fseek(fIn, 0, SEEK_END);
    long inSize = std::ftell(fIn);
    std::fseek(fIn, 0, SEEK_SET);

    if (inSize <= 0) {
        std::fclose(fIn);
        return 2;
    }

    std::vector<unsigned char> inBuf(inSize);
    if (std::fread(inBuf.data(), 1, inSize, fIn) != (size_t)inSize) {
        std::fclose(fIn);
        return 3;
    }
    std::fclose(fIn);

    // 2. Przygotuj bufor na skompresowane dane
    size_t outBufSize = inSize + inSize / 3 + 128; // zapas
    std::vector<unsigned char> outBuf(outBufSize);
    size_t outSize = outBufSize;

    unsigned char props[5];
    size_t propsSize = 5;

    int res = LzmaCompress(
        outBuf.data(), &outSize,
        inBuf.data(), inSize,
        props, &propsSize,
        5,        // level
        0,        // dictSize (0 = domyślny)
        3,        // lc
        0,        // lp
        2,        // pb
        32,       // fb
        1         // numThreads
    );

    if (res != SZ_OK) {
        return 4;
    }

    // 3. Zapisz prosty format: [propsSize(1B)] [props] [compressedSize(8B)] [data]
    FILE* fOut = std::fopen(outFile, "wb");
    if (!fOut) return 5;

    unsigned char propsLen = (unsigned char)propsSize;
    std::fwrite(&propsLen, 1, 1, fOut);
    std::fwrite(props, 1, propsSize, fOut);

    unsigned long long compSize = (unsigned long long)outSize;
    std::fwrite(&compSize, 1, sizeof(compSize), fOut);

    std::fwrite(outBuf.data(), 1, outSize, fOut);
    std::fclose(fOut);

    return 0;
}

__declspec(dllexport)
int DecryptAndDecompress(const char* inFile,
                         const char* outFolder,
                         const char* password)
{
    // Na razie ignorujemy password – najpierw ogarniemy dekompresję.
    // 1. Wczytaj cały plik
    FILE* fIn = std::fopen(inFile, "rb");
    if (!fIn) return 1;

    std::fseek(fIn, 0, SEEK_END);
    long fileSize = std::ftell(fIn);
    std::fseek(fIn, 0, SEEK_SET);

    if (fileSize <= 0) {
        std::fclose(fIn);
        return 2;
    }

    std::vector<unsigned char> fileBuf(fileSize);
    if (std::fread(fileBuf.data(), 1, fileSize, fIn) != (size_t)fileSize) {
        std::fclose(fIn);
        return 3;
    }
    std::fclose(fIn);

    size_t offset = 0;

    // 2. Odczytaj props
    if (offset + 1 > (size_t)fileSize) return 4;
    unsigned char propsLen = fileBuf[offset++];
    if (offset + propsLen > (size_t)fileSize) return 5;

    unsigned char props[5] = {0};
    if (propsLen > 5) return 6;
    std::memcpy(props, fileBuf.data() + offset, propsLen);
    offset += propsLen;

    // 3. Odczytaj rozmiar skompresowanych danych
    if (offset + sizeof(unsigned long long) > (size_t)fileSize) return 7;
    unsigned long long compSize = 0;
    std::memcpy(&compSize, fileBuf.data() + offset, sizeof(compSize));
    offset += sizeof(compSize);

    if (offset + compSize > (size_t)fileSize) return 8;

    const unsigned char* compData = fileBuf.data() + offset;

    // 4. Przygotuj bufor na zdekompresowane dane (na razie zgadujemy, np. 10x)
    size_t outBufSize = (size_t)compSize * 10 + 1024;
    std::vector<unsigned char> outBuf(outBufSize);
    size_t outSize = outBufSize;

    int res = LzmaUncompress(
        outBuf.data(), &outSize,
        compData, &compSize,
        props, propsLen
    );

    if (res != SZ_OK) {
        return 9;
    }

    // 5. Zapisz wynik do pliku w outFolder (np. zawsze "output.bin")
    std::string outPath = std::string(outFolder);
    if (!outPath.empty() && outPath.back() != '\\' && outPath.back() != '/')
        outPath += "\\";
    outPath += "output.bin";

    FILE* fOut = std::fopen(outPath.c_str(), "wb");
    if (!fOut) return 10;

    std::fwrite(outBuf.data(), 1, outSize, fOut);
    std::fclose(fOut);

    return 0;
}

} // extern "C"
