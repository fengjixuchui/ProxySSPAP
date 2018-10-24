#ifndef WRITER_FACTORY_H

#pragma once

#include "defines.h"
#include <stdio.h>
#include <time.h>
#include "writer.h"

/// ПРИВАТНЫЙ ЗАГОЛОВОЧНЫЙ!
/// ИСПОЛЬЗУЙТЕ ПУБЛИЧНЫЙ <c> #include "logger.h>" </c>

/// Фабрика писателя
HRESULT BuildWriter(
	LOG_WRITER_TYPE type,
	PLOG_WRITER_METHODS * writer
);

/// Освободим все ресурсы выделенные фабрикой
VOID FreeWriter(
	VOID
);

#pragma region FILE LOG WRITER
/// <summary> Инициализарует путь к файлу и флаги.</summary>
HRESULT FileLogWriterInit(
	_In_ LPWSTR wsResourceName,
	_In_ LPCWSTR flags
);

/// <summary> Записываем буффер на диск</summary>
HRESULT FileLogWriterFlash(
	_In_bytecount_(ulBufferToLogSize) LPBYTE pbBufferToLog,
	_In_ ULONG ulBufferToLogSize
);

/// <summary> Очищаем выделенные ресурсы </summary>
VOID FileLogWriterClose(
	VOID
);
#pragma endregion

#pragma region CONSOLE LOG WRITER
/// TODO
#pragma endregion

#pragma region SYSLOG LOG WRITER
/// TODO
#pragma endregion

#endif // !WRITER_FACTORY_H