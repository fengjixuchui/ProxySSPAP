/*
* This is a personal academic project. Dear PVS-Studio, please check it.
* PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
*/

#include "stdafx.h"

EXTERN_C_START

#include "logger.h"
#include <assert.h>
#include "writer_factory.h"
#include <time.h>
#include <fcntl.h> 

#pragma warning(disable: 4996)

#define BUFFER_SIZE			0x1000
#define SYSTEM_ROOT_ENV		L"SYSTEMROOT"

static PLOG_WRITER_METHODS logger = NULL;

HRESULT LoggerInit(LOG_WRITER_TYPE type, LPCWSTR ResourceName)
{
	CHECK_STATUS_INIT(S_OK);
	WCHAR 				szPath[MAX_PATH* sizeof(WCHAR)] = { 0 };
	LPCWCHAR			logExt = L".log";
	ULONG				logExtLen = (ULONG)sizeof(TCHAR) * (ULONG)wcslen(logExt);

	assert(logger == NULL);

	if (wcscpy_s(szPath, wcslen(ResourceName) + sizeof(WCHAR), ResourceName) != 0)
	{
		CHECK_STATUS_FROM_WIN32();
		goto Cleanup;

	}

	if (wcscat_s(szPath, wcslen(szPath) + wcslen(logExt) + sizeof(WCHAR), logExt) != 0)
	{
		CHECK_STATUS_FROM_WIN32();
		goto Cleanup;
	}

//#ifdef LOG_BY_RUNTIME_NAME
//	IMAGE_DOS_HEADER __ImageBase
//	UNREFERENCED_PARAMETER(ResourceName);
//	E_CHECK_GOTO(
//		GetModuleFileName((HINSTANCE)&__ImageBase, szPath, MAX_PATH),
//		Cleanup,
//		NULL
//	);
//
//	E_CHECK(
//		memcpy_s(szPath + wcslen(szPath) - wcslen(logExt), logExtLen, logExt, logExtLen) == S_OK,
//		HRESULT_FROM_WIN32(GetLastError()),
//		NULL
//	);
//#else
//	LPWSTR lpLocalBufferSystemRoot[MAX_PATH] = { 0 };
//	LPWSTR lpLocalBufferPath = L"\\Logs\\";
//
//
//	DWORD dwRet = GetEnvironmentVariable(SYSTEM_ROOT_ENV, szPath, MAX_PATH);
//
//	if (0 == dwRet)
//	{
//		CHECK_STATUS_VAR = GetLastError();
//		if (ERROR_ENVVAR_NOT_FOUND == CHECK_STATUS_VAR)
//		{
//			printf("Environment variable does not exist.\n");
//		}
//		goto Cleanup;
//	}
//	else
//	{
//		wcscat_s(szPath, wcslen(szPath) + wcslen(lpLocalBufferPath) + sizeof(WCHAR), lpLocalBufferPath);
//		wcscat_s(szPath, wcslen(szPath) + wcslen(ResourceName) + sizeof(WCHAR), ResourceName);
//		wcscat_s(szPath, wcslen(szPath) + wcslen(logExt) + sizeof(WCHAR), logExt);
//	}
//
//#endif

	NT_CHECK_GOTO(
		BuildWriter(type, &logger),
		Cleanup,
		NULL
	);

	logger->init(szPath, L"a+");

Cleanup:
	CHECK_STATUS_EXIT();
}

HRESULT LoggerWrite(PVOID pvBuffer, ULONG ulSize)
{
	CHECK_STATUS_INIT(S_OK);

	assert(logger != NULL);

	NT_CHECK(
		logger->flash(pvBuffer, ulSize),
		NULL
	);

	CHECK_STATUS_EXIT();
}

VOID LoggerFree(VOID)
{
	assert(logger != NULL);

	logger->close();
	FreeWriter();
}

HRESULT Log(
	_In_ LEVEL_LOG level,
	_In_ LPCWSTR pwMsg,
	_In_ ...
)
{
	CHECK_STATUS_INIT(S_OK);
	WCHAR	pwTimeBuffer[0x40] = { 0 }; // 64Б для буфера
	WCHAR	pwBuffer[BUFFER_SIZE] = { 0 }; // 4КБ для буфера
	WCHAR	pwMsgBuffer[BUFFER_SIZE] = { 0 }; // 4КБ для буфера
	va_list args;
	const time_t tCurrentTime = time(NULL);

	if (pwMsg == NULL)
	{
		return S_OK;
	}

	if (_wctime_s(pwTimeBuffer, 0x40, &tCurrentTime) != 0)
	{
		return(HRESULT_FROM_WIN32(GetLastError()));
	}

	
	va_start(args, pwMsg);

	wvsprintfW(pwMsgBuffer, pwMsg, args);

	va_end(args);
	
	wcscat(pwBuffer, L"[");	
	wcsncpy_s(pwBuffer+ wcslen(L"["), BUFFER_SIZE-1, pwTimeBuffer, wcslen(pwTimeBuffer) - 1/*уберем '\n' */);
	wcscat(pwBuffer, L"][");
	switch (level)
	{
	case DBG:
		wcscat(pwBuffer, L"DBG] ");
		break;
	case TRACE:
		wcscat(pwBuffer, L"TRACE] ");
		break;
	case WARNING:
		wcscat(pwBuffer, L"WARNG] ");
		break;
	case ERR:
		wcscat(pwBuffer, L"ERROR] ");
		break;
	case INFO:
		wcscat(pwBuffer, L"INFOR] ");
		break;
	default:
		wcscat(pwBuffer, L"UNKWN] ");		
	}
	wcscat(pwBuffer, pwMsgBuffer);
	wcscat(pwBuffer, L"\r\n");


	EnterCriticalSection(&logger->csLock);
	CHECK_STATUS_VAR = logger->flash((LPBYTE)pwBuffer, WCSBYTE_UL(pwBuffer));
	LeaveCriticalSection(&logger->csLock);

	CHECK_STATUS_EXIT();
}


HRESULT HexDump(
	_In_ LPCWSTR pwMsg,

	_In_ PVOID pvData,
	_In_ ULONG ulSize
)
{
	CHECK_STATUS_INIT(S_OK);
	size_t i;

	WCHAR wCommonBuffer[BUFFER_SIZE] = { 0x0000 };
	WCHAR tmpBuffer[0xFF] = { 0x0000 };
	WCHAR wBuffer[0xFF] = { 0x0000 };
	LPSTR pcPointerConst = (LPSTR)pvData;

	if (pvData == NULL)
	{
		return S_OK;
	}
	
	
	// Output description if given.
	if (pwMsg != NULL) {
		wsprintfW(tmpBuffer, L"------------------%s--------------------\n", pwMsg);
		wcscat(wCommonBuffer, tmpBuffer);
	}
		
	for (i = 0; i < ulSize; i++) {
		if ((i % 16) == 0) {			
			if (i != 0) {					
				wcscat(wCommonBuffer, wBuffer);
				wcscat(wCommonBuffer, L"\n");				
			}
				
			// Output the offset.
			wsprintfW(tmpBuffer, L" %04X ", i);
			wcscat(wCommonBuffer, tmpBuffer);
			ZeroMemory(tmpBuffer, (ULONG)(0xFF * sizeof(WCHAR)));
		}
	
		// Now the hex code for the specific character.

		swprintf(tmpBuffer, 3*sizeof(WCHAR), L"%.2hX", pcPointerConst[i]);
		wcscat(wCommonBuffer, L" ");
		wcscat(wCommonBuffer, tmpBuffer+(wcslen(tmpBuffer) - 2 ));
		ZeroMemory(tmpBuffer, (ULONG)(0xFF * sizeof(WCHAR)));
	
		wBuffer[(i % 16) + 1] = L'\n';
	}
	

	wcscat(wCommonBuffer, tmpBuffer);
	ZeroMemory(tmpBuffer, (ULONG)(0xFF * sizeof(WCHAR)));

	if (pwMsg != NULL) {
		wsprintfW(tmpBuffer, L"\n------------------%s--------------------\n", pwMsg);
		wcscat(wCommonBuffer, tmpBuffer);
	}

	// TODO неблокирующий ввод-вывод для сохранения естественной очереди синхронизации ABC
	EnterCriticalSection(&logger->csLock);
	CHECK_STATUS_VAR = logger->flash((LPBYTE)wCommonBuffer, WCSBYTE_UL(wCommonBuffer));
	LeaveCriticalSection(&logger->csLock);

	CHECK_STATUS_EXIT();
}

EXTERN_C_END