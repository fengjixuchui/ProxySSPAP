#ifndef _DEFINES_
#define _DEFINES_

#pragma once

#include "logger.h"
EXTERN_C_START

#define WITHOUT_PADDING

#ifndef WITHOUT_PADDING
#define  PACK_ON(SZ)		__declspec(align(SZ))
#define  PACK_ON_PTR64()	PACK_ON(sizeof(PVOID64))
#else
#define  PACK_ON(SZ)
#define  PACK_ON_PTR64()
#endif

#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(exp)					((NULL != (exp)))
#endif

#ifndef FREE
#define FREE(p)	free(p)
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(p)				\
	do{								\
		if(ARGUMENT_PRESENT(p)){	\
			free(p);				\
			p = NULL;				\
		}							\
	}while(0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == SEC_E_OK)
#endif

#ifndef NT_ERROR
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)
#endif

/// <summary>ћакросы проверок разного рода выражений с логированием</summary>
#ifndef E_CHECK
 /// ѕроверим есть ли макрос лоигровани€
#ifndef LOG_ERROR
 #error If y want use this features you must define MACRO(LOG_ERROR)
#endif // !LOG_ERROR


#define CHECK_STATUS_VAR									\
	__GLOBAL_STATUS
#define CHECK_STATUS_INIT(def)								\
	HRESULT CHECK_STATUS_VAR = def
#define CHECK_NTSTATUS_INIT(def)							\
	NTSTATUS CHECK_STATUS_VAR = def
#define CHECK_STATUS_EXIT()									\
	return(CHECK_STATUS_VAR)
#define CHECK_STATUS_FROM_WIN32()							\
	CHECK_STATUS_VAR = HRESULT_FROM_WIN32(GetLastError())

#define CHECK_WITH_INSTR(expr,instr,msg,...)				\
	while(!(expr)){											\
		LOG_ERROR(msg, ##__VA_ARGS__);						\
		instr;												\
		break;												\
	}

#define CHECK_WITH_INSTR_AND_STATUS(expr,stat,instr,msg,...)\
	while(!(stat = (expr))){								\
		LOG_ERROR(msg, ##__VA_ARGS__);						\
		instr;												\
		break;												\
	}

#define CHECK_WITH_INSTR_ST_COND(cond,expr,stat,instr,msg,...)\
	while(!cond(stat = (expr))){							\
		LOG_ERROR(msg, ##__VA_ARGS__);						\
		instr;												\
		break;												\
	}

#define E_CHECK(expr,status,msg,...)						\
	CHECK_WITH_INSTR(										\
		expr,												\
		return status,										\
		msg,												\
		##__VA_ARGS__										\
	)

#define E_CHECK_GOTO(expr,label,msg,...)					\
	CHECK_WITH_INSTR_AND_STATUS(							\
		expr,												\
		CHECK_STATUS_VAR,									\
		goto label,											\
		msg,												\
		##__VA_ARGS__										\
	)

#define NT_CHECK(expr,msg,...)								\
	CHECK_WITH_INSTR_ST_COND(								\
		NT_SUCCESS,											\
		expr,												\
		CHECK_STATUS_VAR,									\
		return CHECK_STATUS_VAR,							\
		msg,												\
		##__VA_ARGS__										\
	)

#define NT_CHECK_GOTO(expr,label,msg,...)					\
	CHECK_WITH_INSTR_ST_COND(								\
		NT_SUCCESS,											\
		expr,												\
		CHECK_STATUS_VAR,									\
		goto label,											\
		msg,												\
		##__VA_ARGS__										\
	)
#endif


/// <summary>ѕодсчет количества байт в строке widechar</summary>
#ifndef WCSBYTE_UL
 #define WCSBYTE_UL(wcBuffer)								\
	(ULONG)(wcslen((LPCWSTR)wcBuffer)*sizeof(WCHAR))

#endif // !WCSBYTE_UL
EXTERN_C_END

#endif // _DEFINES_
