#include <windows.h>
#include <string>

#include "../7zip-SDK/Common/MyCom.h"
#include "../7zip-SDK/Common/MyInitGuid.h"
#include "../7zip-SDK/Common/FileStreams.h"
#include "../7zip-SDK/Common/IntToString.h"
#include "../7zip-SDK/Common/UTFConvert.h"

#include "../7zip-SDK/7zip/Archive/7z/7zHandler.h"
#include "../7zip-SDK/7zip/Archive/7z/7zIn.h"
#include "../7zip-SDK/7zip/Archive/7z/7zOut.h"

#include "../7zip-SDK/7zip/Common/ArchiveOpenCallback.h"
#include "../7zip-SDK/7zip/Common/ArchiveExtractCallback.h"
#include "../7zip-SDK/7zip/Common/ArchiveUpdateCallback.h"

extern "C" __declspec(dllexport)
int CompressAndEncryptFile(const char* inFile, const char* outFile, const char* password)
{
    try
    {
        UString uInFile = GetUnicodeString(inFile);
        UString uOutFile = GetUnicodeString(outFile);
        UString uPassword = GetUnicodeString(password);

        // Output stream
        COutFileStream *outStreamSpec = new COutFileStream;
        CMyComPtr<IOutStream> outStream(outStreamSpec);

        if (!outStreamSpec->Open(uOutFile))
            return 2;

        // Update callback
        CArchiveUpdateCallback *updateCallbackSpec = new CArchiveUpdateCallback;
        CMyComPtr<IArchiveUpdateCallback2> updateCallback(updateCallbackSpec);

        updateCallbackSpec->PasswordIsDefined = true;
        updateCallbackSpec->Password = uPassword;

        updateCallbackSpec->FilePaths.Add(uInFile);
        updateCallbackSpec->Init();

        // 7z handler
        C7zHandler *handlerSpec = new C7zHandler;
        CMyComPtr<IInArchive> handler(handlerSpec);

        HRESULT result = handler->UpdateItems(outStream, 1, updateCallback);

        if (result != S_OK)
            return 3;

        return 0; // OK
    }
    catch (...)
    {
        return 1;
    }
}

extern "C" __declspec(dllexport)
int DecompressAndDecryptFile(const char* archiveFile, const char* outFolder, const char* password)
{
    try
    {
        UString uArchive = GetUnicodeString(archiveFile);
        UString uOutFolder = GetUnicodeString(outFolder);
        UString uPassword = GetUnicodeString(password);

        // Input stream
        CInFileStream *inStreamSpec = new CInFileStream;
        CMyComPtr<IInStream> inStream(inStreamSpec);

        if (!inStreamSpec->Open(uArchive))
            return 2;

        // 7z handler
        C7zHandler *handlerSpec = new C7zHandler;
        CMyComPtr<IInArchive> handler(handlerSpec);

        CArchiveOpenCallback *openCallbackSpec = new CArchiveOpenCallback;
        CMyComPtr<IArchiveOpenCallback> openCallback(openCallbackSpec);

        HRESULT result = handler->Open(inStream, 0, openCallback);
        if (result != S_OK)
            return 3;

        // Extract callback
        CArchiveExtractCallback *extractCallbackSpec =
            new CArchiveExtractCallback(handler, uOutFolder);
        CMyComPtr<IArchiveExtractCallback> extractCallback(extractCallbackSpec);

        extractCallbackSpec->PasswordIsDefined = true;
        extractCallbackSpec->Password = uPassword;

        result = handler->Extract(NULL, (UInt32)(Int32)-1, false, extractCallback);

        if (result != S_OK)
            return 4;

        return 0; // OK
    }
    catch (...)
    {
        return 1;
    }
}
