#include "CPP/7zip/Archive/7z/7zIn.h"
#include "CPP/7zip/Archive/7z/7zOut.h"
#include "CPP/7zip/Common/FileStreams.h"
#include "CPP/7zip/Common/StreamObjects.h"
#include "CPP/7zip/Common/StdOutStream.h"
#include "CPP/7zip/7zip/Common/FilePathAutoRename.h"
#include "CPP/7zip/7zip/Common/ArchiveExtractCallback.h"
#include "CPP/7zip/7zip/Common/ArchiveOpenCallback.h"
#include "CPP/7zip/7zip/Common/ArchiveUpdateCallback.h"

#include <windows.h>
#include <string>

extern "C" __declspec(dllexport)
int CompressAndEncryptFile(const char* inFile, const char* outFile, const char* password)
{
    try
    {
        UString archiveName = GetUnicodeString(outFile);
        UString srcFile = GetUnicodeString(inFile);

        COutFileStream *outStreamSpec = new COutFileStream;
        CMyComPtr<IOutStream> outStream(outStreamSpec);

        if (!outStreamSpec->Open(archiveName))
            return 2;

        CArchiveUpdateCallback *updateCallbackSpec = new CArchiveUpdateCallback;
        CMyComPtr<IArchiveUpdateCallback2> updateCallback(updateCallbackSpec);

        updateCallbackSpec->PasswordIsDefined = true;
        updateCallbackSpec->Password = GetUnicodeString(password);

        updateCallbackSpec->FilePaths.Add(srcFile);
        updateCallbackSpec->Init();

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
