#pragma once

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
int CompressAndEncryptFile(const char* inFile,
                           const char* outFile,
                           const char* password);

__declspec(dllexport)
int DecompressAndDecryptFile(const char* archiveFile,
                             const char* outFolder,
                             const char* password);

#ifdef __cplusplus
}
#endif
