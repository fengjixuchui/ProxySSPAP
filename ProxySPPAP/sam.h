#ifndef SAM_USER_TOKEN_INFO_H
#define SAM_USER_TOKEN_INFO_H

#pragma once
#include "internals.h"
#include <LM.h>

/// <summary>Токен для обработки данных.</summary>
typedef HANDLE OEM_SAM_HANDLE;
typedef OEM_SAM_HANDLE *POEM_SAM_HANDLE;

/// <summary>Инициализирует ресурсы связанные с samlib.</summary>
NTSTATUS SamAllocateResource(VOID);

/// <summary>Освобождает ресурсы связанные с samlib.</summary>
VOID SamFreeResource(VOID);

/// <summary>Открывает соединение с БД SAM.</summary>
_Check_return_ NTSTATUS NTAPI InitSamDatabase(
	_Out_ POEM_SAM_HANDLE pSamTokenHandler, LPCWSTR pwsDomain
);

/// <summary>
/// Устанавливает контекст пользовтеля. В рамках установленного конекста будут выполнятся все последующие операции пользователя.
/// Конекст привязан к <param>OEM_SAM_HANDLE</param>.
/// </summary>
/// <remarks>Следует очень отвественно отнестись к конексту пользователя, 
/// так как соединение к БД SAN будет открыто при инициализации:<function>InitSamDatabase</function>.
/// Т.е. использовать одит и тот же хэндлер  <param>OEM_SAM_HANDLE</param> для разных контекстов крайне не рекомендуется.
/// </remarks>
/// <todo>Вынести в отдельную сущность конекст пользователя.</todo>
_Check_return_ NTSTATUS NTAPI SetupUserContext(
	_In_ OEM_SAM_HANDLE hSamTokenHandler,
	_In_ LPCWSTR psuUsername
);

/// <summary>
/// Создает токен идентификации указанного типа
/// </summary>
/// <remarks>
/// Версия 1. Поддерживается только структура LSA_TOKEN_INFORMATION_V2.
/// Память должна быть выделенна в непрерывном блоке
/// </remarks>
_Check_return_ NTSTATUS NTAPI AllocateTokenInformation(
	_In_ OEM_SAM_HANDLE pSamTokenHandler,
	_In_ LSA_TOKEN_INFORMATION_TYPE tokenInforamtionType,
	_When_(tokenInforamtionType == LsaTokenInformationNull, _Out_bytecapcount_(sizeof(LSA_TOKEN_INFORMATION_NULL)))
	_When_(tokenInforamtionType == LsaTokenInformationV1, _Out_bytecapcount_(sizeof(LSA_TOKEN_INFORMATION_V1)))
	_When_(tokenInforamtionType == LsaTokenInformationV2, _Out_bytecapcount_(sizeof(LSA_TOKEN_INFORMATION_V2)))
	_When_(tokenInforamtionType == LsaTokenInformationV3, _Out_bytecapcount_(sizeof(LSA_TOKEN_INFORMATION_V3)))
	PVOID * tokenInformation
);

/// <summary>
/// Создает профиль пользователя
/// </summary>
/// <remarks>
/// Версия 1. профиль формата PMSV1_0_INTERACTIVE_PROFILE
/// </remarks>
NTSTATUS AllocateInteractiveProfile(
	_In_ PLSA_CLIENT_REQUEST ClientRequest,
	_Out_bytecapcount_(ProfileBufferSize) PVOID *ProfileBuffer,
	_Out_ PULONG ProfileBufferSize,
	_In_ OEM_SAM_HANDLE pSamTokenHandler
);

/// <summary>
/// Освобождает все ресырсы выделенные  InitSamDatabase.
/// </summary>
VOID FreeSamDatabase(
	OEM_SAM_HANDLE SamTokenHandler
);

#endif // !SAM_USER_TOKEN_INFO_H