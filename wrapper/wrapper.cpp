#include <windows.h>
#include <string>

#include "MyCom.h"
#include "MyInitGuid.h"
#include "FileStreams.h"
#include "IntToString.h"
#include "UTFConvert.h"

#include "7zHandler.h"
#include "7zIn.h"
#include "7zOut.h"

#include "ArchiveOpenCallback.h"
#include "ArchiveExtractCallback.h"
#include "ArchiveUpdateCallback.h"


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
