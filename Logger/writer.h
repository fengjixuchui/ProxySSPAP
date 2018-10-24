#ifndef WRITER_H

#pragma once

#include <stdio.h>
#include <time.h>

#pragma region WRITER BASE

/// ¬озможно пригодитс€ ресурс дл€ выделени€ внутренних структур
typedef HANDLE LOG_HANDLE, *PLOG_HANDLE;

/// --- Callbacks дл€ управлени€ ---
typedef NTSTATUS(LOG_WRITER_INIT)(
	_In_ LPWSTR wsResourceName,
	_In_ LPCWSTR flags
	);

typedef NTSTATUS(LOG_WRITER_FLASH)(
	_In_bytecount_(ulBufferToLogSize) LPBYTE pbBufferToLog,
	_In_ ULONG ulBufferToLogSize
	);

typedef VOID(LOG_WRITER_CLOSE)(
	VOID
	);
/// --------------------------------

typedef LOG_WRITER_INIT *PLOG_WRITER_INIT;
typedef LOG_WRITER_FLASH *PLOG_WRITER_FLASH;
typedef LOG_WRITER_CLOSE *PLOG_WRITER_CLOSE;

/// “ип механизма логировани€
typedef enum __LOG_WRITER_TYPE {
	Console,
	File,
	Syslog
} LOG_WRITER_TYPE, *PLOG_WRITER_TYPE;

/// ћетоды управлени€ логированием
typedef struct __LOG_WRITER_METHODS { 
	ULONG id;				// зарезервированно дл€ идентификации писател€ в глобальном списке всех writer'ов

	LOG_WRITER_TYPE	logType;

	CRITICAL_SECTION csLock;

	PLOG_WRITER_INIT init;
	PLOG_WRITER_FLASH flash;
	PLOG_WRITER_CLOSE close;

	PVOID protocolHandler;	// «арезервированно дл€ дополнительных операций в рамках протокола, который реализует конкретный WRITER
} LOG_WRITER_METHODS, *PLOG_WRITER_METHODS;

#pragma endregion


#endif // !WRITER_H