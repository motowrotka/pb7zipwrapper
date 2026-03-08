#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) int __stdcall EncryptAndCompress(const char* inFile, const char* outFile, const char* password);
__declspec(dllexport) int __stdcall DecryptAndDecompress(const char* inFile, const char* outFolder, const char* password);

#ifdef __cplusplus
}
#endif
