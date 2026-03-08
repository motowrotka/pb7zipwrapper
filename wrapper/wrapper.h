#pragma once

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
int CompressAndEncryptFile(const char* inFile,
                           const char* outFile,
                           const char* password);

#ifdef __cplusplus
}
#endif
