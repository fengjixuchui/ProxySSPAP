#ifndef __LOGGER_APP__
#define __LOGGER_APP__

EXTERN_C_START

#pragma warning(disable: 4010)
#pragma once

#include "writer.h"

typedef enum __LEVEL_LOG {
	INFO = 0,
	ERR,
	WARNING,
	DBG,
	TRACE
} LEVEL_LOG;

/* Инициализируем лог */
HRESULT LoggerInit(
	_In_ LOG_WRITER_TYPE type, LPCWSTR ResourceName
);

/* Логируем сообщение */
HRESULT Log(
	_In_ LEVEL_LOG level,
	_In_ LPCWSTR pwMsg,
	_In_ ...
);

/* Логируем буффер определенной длинны */
HRESULT HexDump(
	_In_ LPCWSTR pwMsg,
	_In_ PVOID pvData,
	_In_ ULONG ulSize
);

/* Освобождаем ресурсы */
VOID LoggerFree(
	VOID
);


/* ------------------- Уровни логирования ------------------- */

/* Логируем сообщение ошибки */
#if defined(_DEBUG) && !defined(NO_LOG)
#define LOG_ERROR(msg, ...) \
	Log(ERR,  msg, ## __VA_ARGS__)

/* Логируем сообщение предупреждения */
#define LOG_WARNING(msg, ...) \
	Log(WARNING, msg, ## __VA_ARGS__)

/* Логируем сообщение информации */
#define LOG_INFO(msg, ...) \
	Log(INFO, msg, ## __VA_ARGS__)

/* Логируем сообщение отладки */
#define LOG_DEBUG(msg, ...) \
	Log(DBG, msg, ## __VA_ARGS__)

/* Логируем сообщение трасировки */
#define LOG_TRACE(msg, ...) \
	Log(TRACE, (msg), ##__VA_ARGS__)

/*Логируем произвольный буфер в HEX*/
#define LOG_DUMP(msg, data, size)	\
	HexDump((msg), (data), (size))

/*Лог функции в контексте которой вызван макрос*/
#define LOG_FUNCTION_CALL()	\
	LOG_TRACE( L"" __FUNCTIONW__  )

#else
#define LOG_ERROR(msg, ...) \
	UNREFERENCED_PARAMETER(msg)
#define LOG_WARNING(msg, ...)\
	UNREFERENCED_PARAMETER(msg) 
#define LOG_INFO(msg, ...)\
	UNREFERENCED_PARAMETER(msg)
#define LOG_DEBUG(msg, ...) \
	UNREFERENCED_PARAMETER(msg)
#define LOG_TRACE(msg, ...) \
	UNREFERENCED_PARAMETER(msg)
#define LOG_DUMP(msg, data, size)	\
	UNREFERENCED_PARAMETER(msg);\
	UNREFERENCED_PARAMETER(data);\
	UNREFERENCED_PARAMETER(size)
#define LOG_FUNCTION_CALL()	\
	LOG_TRACE( L"" __FUNCTIONW__  )
#endif
/* ----------------------------------------------------------- */

EXTERN_C_END

#endif //