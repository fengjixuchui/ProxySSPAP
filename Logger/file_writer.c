/*
* This is a personal academic project. Dear PVS-Studio, please check it.
* PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
*/
#include "stdafx.h"
#include "writer.h"
#include "writer_factory.h"
#include <wchar.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <share.h>

#define MAX_PATH_LEN				0x0100


/// так быстрее доступ будет
typedef struct PACK_ON(sizeof(WCHAR)) __FILE_LOG {
	LPCWSTR ulFlags;
	WCHAR wcBuffer[MAX_PATH_LEN + 1];
} FILE_LOG, *PFILE_LOG;

PFILE_LOG fileLogResource = NULL;

HRESULT FileLogWriterInit(
	_In_ LPWSTR wsResourceName,
	_In_ LPCWSTR flags
)
{
	CHECK_STATUS_INIT(S_OK);
	ULONG bufferSize = WCSBYTE_UL(wsResourceName);

	E_CHECK(
		(ARGUMENT_PRESENT(fileLogResource = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_LOG)))),
		HRESULT_FROM_WIN32(GetLastError()),
		NULL
	);

	fileLogResource->ulFlags = flags;
	E_CHECK(
		memcpy_s(fileLogResource->wcBuffer, (rsize_t)bufferSize, wsResourceName, (rsize_t)bufferSize) == 0,
		HRESULT_FROM_WIN32(GetLastError()),
		NULL
	);

	CHECK_STATUS_EXIT();
}

HRESULT FileLogWriterFlash(
	_In_bytecount_(ulBufferToLogSize) LPBYTE pbBufferToLog,
	_In_ ULONG ulBufferToLogSize
)
{
	CHECK_STATUS_INIT(S_OK);
	FILE *fDescriptor;
	DWORD dwBytesToWrite = ulBufferToLogSize;
	DWORD dwBytesWritten = 0;

	E_CHECK(
		ARGUMENT_PRESENT(fDescriptor =_wfsopen(fileLogResource->wcBuffer, L"a+t", _SH_DENYNO)),
		HRESULT_FROM_WIN32(CHECK_STATUS_VAR),
		NULL
	);

	E_CHECK_GOTO(
		(fputws(
			(LPWSTR)pbBufferToLog,						
			fDescriptor			
		)) >= 0,
		Error,		
		NULL
	);

Cleanup:
	fclose(fDescriptor);

	CHECK_STATUS_EXIT();
Error:
	printf("Error: dwBytesWritten != dwBytesToWrite\n");
	goto Cleanup;
}

VOID FileLogWriterClose(
	VOID
)
{
	if (ARGUMENT_PRESENT(fileLogResource)) 
	{
		HeapFree(GetProcessHeap(), 0, fileLogResource);
	}
}