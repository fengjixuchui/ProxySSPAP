#include "stdafx.h"
#include "writer_factory.h"
#include <assert.h>

/// <todo> добавить множественное хранение writer'ов, дл€ последующей очитски </todo>
static PLOG_WRITER_METHODS writers = NULL;

HRESULT BuildWriter(
	LOG_WRITER_TYPE type,
	PLOG_WRITER_METHODS * writer
)
{
	CHECK_STATUS_INIT(S_OK);
	
	/// <remarks>
	/// Ёто пока не будет реализованно хранение списка дескрипторов writers, см. объ€вление 
	/// <c>PLOG_WRITER_METHODS writers</c>
	/// </remarks>
	assert(writers == NULL);
	if (ARGUMENT_PRESENT(writers))
	{
		return HRESULT_FROM_NT(STATUS_INTEGER_OVERFLOW);
	}

	switch (type)
	{
	case File:
		E_CHECK(
			ARGUMENT_PRESENT((*writer) = writers = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOG_WRITER_METHODS))),
			HRESULT_FROM_WIN32(GetLastError()),
			NULL
		);

		writers->logType = type;
		writers->init = FileLogWriterInit;
		writers->flash = FileLogWriterFlash;		
		writers->close = FileLogWriterClose;

		InitializeCriticalSection(&writers->csLock);

		break;
	default:
		return HRESULT_FROM_WIN32(E_NOTIMPL);
		break;
	}

	CHECK_STATUS_EXIT();
}

VOID FreeWriter(VOID)
{
	DeleteCriticalSection(&writers->csLock);
	HeapFree(GetProcessHeap(), 0, writers);
}