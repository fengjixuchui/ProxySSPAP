#pragma once

#include <Windows.h>
#include <logger.h>
#include "package.h"

////////////////////////////////////////////////////////////////
/////				ОПРЕДЕЛЕНИЕ MACRO					////////
////////////////////////////////////////////////////////////////

/// определим кучу в 4 килобайта
/// отсекаем лики выделяя непрерывный блок который будет разом освобожден
#define HEAP_SIZE 0x1000

/// <summary>
/// Вызываем LSA функцию из таблицы функций
/// </summary>
#define LSA_CALL(f, ... )  \
	pLsaDispatch->f( ##__VA_ARGS__ )

#pragma region LSA_FUNCTION_POINTERS
/// <summary>
/// Выделяет память в куче. Ожидается, что некоторые данные, переданные обратно в LSA, будут распределены с использованием этой функции.
/// Память, выделенная этой процедурой, должна быть освобождена с помощью функции FreeLsaHeap.
/// </summary>
#define LSA_ALLOCATE_HEAP(LA)						LSA_CALL(AllocateLsaHeap, (LA))

/// <summary>
/// Выделяет память на личной куче.
/// Память, выделенная этой процедурой, должна быть освобождена с помощью функции FreePrivateHeap.
/// </summary>
#define LSA_ALLOCATE_PRIVATE_HEAP_F(LA)				LSA_CALL(AllocatePrivateHeap, (LA))

/// <summary>
/// Освобождает память, выделенную с помощью функции AllocatePrivateHeap.
/// </summary>
#define LSA_FREE_PRIVATE_HEAP_F(PV)					LSA_CALL(FreePrivateHeap, (PV))

/// <summary>
/// Освобождает память из кучи, выделенную ранее через AllocateLsaHeap.
/// </summary>
#define LSA_FREE_HEAP(PV)							LSA_CALL(FreeLsaHeap, (PV))

/// <summary>
/// Выделяет буфер в адресном пространстве клиента. Буферы, выделенные в адресном пространстве клиента,
/// используются для хранения информации, возвращаемой клиенту из пакета проверки подлинности.
/// </summary>
#define LSA_ALLOCATE_CLIENT_BUFFER_F(CR, LR, CBA)	LSA_CALL(AllocateClientBuffer, (CR), (LR), (CBA))

/// <summary>
/// Копирует информацию из буфера в текущем процессе в адресное пространство клиентского процесса.
/// </summary>
#define LSA_COPY_TO_CLIENT_BUFFER_F(CR,L,CBA,BTC)	LSA_CALL(CopyToClientBuffer, (CR), L, CBA, BTC)

/// <summary>
/// Освобождает буфер, ранее выделенный функцией AllocateClientBuffer.
/// </summary>
#define LSA_FREE_CLIENT_BUFFER_F(CR,CBA)			LSA_CALL(FreeClientBuffer, (CR), (CBA))

/// <summary>
/// Функция GetCallInfo извлекает информацию о последнем вызове функции.
/// </summary>
#define LSA_GET_CALL_INFO_F(PV)						LSA_CALL(GetCallInfo, (PV))

/// <summary>
/// Получает дескриптор учетной записи пользователя в базе данных диспетчера учетных записей безопасности (SAM).
/// </summary>
/// <params>
/// _In_ PSECURITY_STRING Name,
/// _In_ SECPKG_NAME_TYPE NameType,
/// _In_ PSECURITY_STRING Prefix,
/// _In_ BOOLEAN AllowGuest,
/// _In_ ULONG Reserved,
/// _Out_ PVOID * UserHandle
/// </params>
#define LSA_OPEN_SAM_USER_F(N,NT,P,AG,R,US)			LSA_CALL(OpenSamUser, N,NT,P,AG,R,US)

/// <summary>
/// Функция GetUserAuthData возвращает данные авторизации для пользователя в одном буфере.
/// </summary>
#define LSA_GET_USER_AUTH_DATA_F(UH,UAD,UADS)		LSA_CALL(GetUserAuthData, (UH),(UAD),(UserAuthDataSize))

/// <summary>
/// Функция GetAuthDataForUser извлекает данные аутентификации для пользователя 
/// из базы данных диспетчера учетных записей безопасности (SAM) и помещает ее в формат, подходящий для функции ConvertAuthDataToToken .
/// </summary>
#define LSA_GET_AUTH_DATA_FOR_USER_F(N,NT,P,AG,R,U) LSA_CALL(GetAuthDataForUser, (N),(NT),(P),(AG),(R),(U))

/// <summary>
/// Функция CloseSamUser закрывает дескриптор учетной записи пользователя диспетчера учетных записей безопасности (SAM).
/// </summary>
#define LSA_CLOSE_SAM_USER_F(PV)					LSA_CALL(CloseSamUser,(UserHandle))

/// <summary>
/// Функция ImpersonateClient вызывается для олицетворения пользователя.
/// </summary>
#define LSA_IMPERSONATE_CLIENT_F()					LSA_CALL(ImpersonateClient)

/// <summary>
/// Создает сеансы входа в систему.
/// Сеанс входа в систему идентифицируется уникальным идентификатором входа(LUID), назначенным сеансу входа в систему.
/// </summary>
#define LSA_CREATE_LOGON_SESSION_F(LID)				LSA_CALL(CreateLogonSession, LID)

/// <summary>
/// Очищает все сеансы входа в систему, созданные при определении того, является ли информация аутентификации пользователя верной.
/// </summary>
#define LSA_DELETE_LOGON_SESSION_F(LID)				LSA_CALL(DeleteLogonSession, LID)

#pragma endregion

////////////////////////////////////////////////////////////////
/////				ОПРЕДЕЛЕНИЕ FUNC					////////
////////////////////////////////////////////////////////////////

/* Выделяем буффер для LSA_STRING*/
LSA_STRING *AllocateLsaStringLsa(
	LPCSTR szString
);

/* Выделяем ьуффер для UNICODE_STRING*/
UNICODE_STRING *AllocateUnicodeStringLsa(
	LPCWSTR szString
);

/* Получаем куски памяти из выделенного монолитного блока*/
LPVOID LsaAllocateHeap(
	ULONG size,
	LPBYTE * ppHeapBase,
	LPBYTE * ppHeapPtr
);

/* указатель на таблицу функций */
extern PLSA_DISPATCH_TABLE pLsaDispatch;

/* указатель загружаемый модуль */
extern HMODULE MsvPackage;

/*  */
extern PSECPKG_FUNCTION_TABLE pMsvTables;

/*  */
extern PLSA_AP_INITIALIZE_PACKAGE MsvLsaApInitializePackage;

/*  */
extern PLSA_AP_LOGON_TERMINATED MsvLsaApLogonTerminated;

/*  */
extern PLSA_AP_LOGON_USER_EX2  MsvLsaApLogonUserEx2;
