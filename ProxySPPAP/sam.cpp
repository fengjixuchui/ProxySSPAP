/*
* This is a personal academic project. Dear PVS-Studio, please check it.
* PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
*/
#include "stdafx.h"
EXTERN_C_START
#include "sam.h"
#include <Logger.h>
#include <defines.h>
#include "internals.h"
#include "ntsam.h"
#include <DsGetDC.h>

#pragma warning(disable:4996)

#define SAM_USER(v)					v.pUserAllInformation
#define PSAM_USER(v)				((v)->pUserAllInformation)

#define DEFINE_SAM_DATA_CAST(name,v)	\
	PSAM_USER_DATA name = (PSAM_USER_DATA)v

/// <summary>Общая информация о запрошенном пользователе.</summary>
/// <remarks>Выравнивание для быстрого доступа к указателям.</remarks>
typedef struct _SAM_USER_DATA
{
	SAM_HANDLE					hSam;
	SAM_HANDLE					hDomine;
	SAM_HANDLE					hUser;

	PSAM_RID_ENUMERATION		pUserRID;
	PUSER_ALL_INFORMATION		pUserAllInformation;

} SAM_USER_DATA, *PSAM_USER_DATA;

static NTSTATUS GetPrimaryGroup(
	_In_ PSAM_USER_DATA pSamData,
	_In_ PSID UserSid,
	_Out_ PSID *PrimarySid,
	_Inout_ LPBYTE *ppHeapBase,
	_Inout_ LPBYTE *ppHeapPtr
);

static HINSTANCE hSamLibModule;

static PSAM_CONNECT LsaSamConnect = NULL;
static PSAM_OPEN_DOMAIN LsaSamOpenDomain = NULL;
static PSAM_OPEN_USER LsaSamOpenUser = NULL;
static PSAM_QUERY_INFO_USER LsaSamQueryInformationUser = NULL;
static PSAM_ENUMERATE_USERS_IN_DOMAIN LsaSamEnumerateUsersInDomain = NULL;
static PSAM_LOOKUP_DOMAIN_IN_SERVER LsaSamLookupDomainInSamServer = NULL;
static PSAM_CLOSE_HANDLE LsaSamCloseHandle = NULL;
static PSAM_FREE_MEMORY LsaSamFreeMemory = NULL;
static PSAM_RID_TO_SID LsaSamRidToSid = NULL;
static PSAM_OPEN_GROUP LsaSamOpenGroup = NULL;
static PSAM_GET_GROUPS_FOR_USER LsaSamGetGroupsForUser = NULL;


static LSA_HANDLE					hLsaPolicy;
static PPOLICY_ACCOUNT_DOMAIN_INFO pPolicyDomainInfo = NULL;

#define SAM_REQ_FUNCTION_CHECK()								\
	assert(ARGUMENT_PRESENT(LsaSamConnect));					\
	assert(ARGUMENT_PRESENT(LsaSamOpenDomain));					\
	assert(ARGUMENT_PRESENT(LsaSamOpenUser));					\
	assert(ARGUMENT_PRESENT(LsaSamQueryInformationUser));		\
	assert(ARGUMENT_PRESENT(LsaSamEnumerateUsersInDomain));		\
	assert(ARGUMENT_PRESENT(LsaSamLookupDomainInSamServer));	\
	assert(ARGUMENT_PRESENT(LsaSamCloseHandle));				\
	assert(ARGUMENT_PRESENT(LsaSamFreeMemory));					\
	assert(ARGUMENT_PRESENT(LsaSamRidToSid));					\
	assert(ARGUMENT_PRESENT(LsaSamOpenGroup));					\
	assert(ARGUMENT_PRESENT(LsaSamGetGroupsForUser))				

NTSTATUS SamAllocateResource(VOID)
{
	LOG_FUNCTION_CALL();
	CHECK_STATUS_INIT(S_OK);
	LOG_TRACE(L"Load samlib DLL");
	hSamLibModule = LoadLibraryW(L"samlib.dll");
	assert(hSamLibModule != NULL);
	if (hSamLibModule == NULL)
	{
		LOG_ERROR(L"Load library SAMLIB.DLL going fail");
		return STATUS_NO_MEMORY;
	}

	LOG_TRACE(L"load proc adress LsaSamConnect");
	LsaSamConnect = (PSAM_CONNECT)GetProcAddress(hSamLibModule, "SamConnect");
	LOG_TRACE(L"load proc adress SamOpenDomain");
	LsaSamOpenDomain = (PSAM_OPEN_DOMAIN)GetProcAddress(hSamLibModule, "SamOpenDomain");
	LOG_TRACE(L"load proc adress SamOpenUser");
	LsaSamOpenUser = (PSAM_OPEN_USER)GetProcAddress(hSamLibModule, "SamOpenUser");
	LOG_TRACE(L"load proc adress SamQueryInformationUser");
	LsaSamQueryInformationUser = (PSAM_QUERY_INFO_USER)GetProcAddress(hSamLibModule, "SamQueryInformationUser");
	LOG_TRACE(L"load proc adress SamEnumerateUsersInDomain");
	LsaSamEnumerateUsersInDomain = (PSAM_ENUMERATE_USERS_IN_DOMAIN)GetProcAddress(hSamLibModule, "SamEnumerateUsersInDomain");
	LOG_TRACE(L"load proc adress SamLookupDomainInSamServer");
	LsaSamLookupDomainInSamServer = (PSAM_LOOKUP_DOMAIN_IN_SERVER)GetProcAddress(hSamLibModule, "SamLookupDomainInSamServer");
	LOG_TRACE(L"load proc adress SamCloseHandle");
	LsaSamCloseHandle = (PSAM_CLOSE_HANDLE)GetProcAddress(hSamLibModule, "SamCloseHandle");
	LOG_TRACE(L"load proc adress SamFreeMemory");
	LsaSamFreeMemory = (PSAM_FREE_MEMORY)GetProcAddress(hSamLibModule, "SamFreeMemory");
	LOG_TRACE(L"load proc adress SamRidToSid");
	LsaSamRidToSid = (PSAM_RID_TO_SID)GetProcAddress(hSamLibModule, "SamRidToSid");
	LOG_TRACE(L"load proc adress SamOpenGroup");
	LsaSamOpenGroup = (PSAM_OPEN_GROUP)GetProcAddress(hSamLibModule, "SamOpenGroup");
	LOG_TRACE(L"load proc adress SamGetGroupsForUser");
	LsaSamGetGroupsForUser = (PSAM_GET_GROUPS_FOR_USER)GetProcAddress(hSamLibModule, "SamGetGroupsForUser");

	
	CHECK_STATUS_EXIT();
}

VOID SamFreeResource(VOID)
{
	if (ARGUMENT_PRESENT(hSamLibModule))
	{
		FreeLibrary(hSamLibModule);
		hSamLibModule = NULL;
	}

	if (ARGUMENT_PRESENT(pPolicyDomainInfo))
	{
		LOG_TRACE(L"LsaFreeMemory pPolicyDomainInfo");
		LsaFreeMemory(pPolicyDomainInfo);
	}
}

NTSTATUS InitSamDatabase(
	POEM_SAM_HANDLE pSamTokenHandler, 
	LPCWSTR pwsDomain
)
{
	CHECK_STATUS_INIT(STATUS_SUCCESS);
	PSAM_USER_DATA			pSamUserData = NULL;
	UNREFERENCED_PARAMETER(pwsDomain);
	LSA_OBJECT_ATTRIBUTES	ObjectAttributes;

	LOG_TRACE(L"ALLOCATE Sam user data");
	if ((pSamUserData = (PSAM_USER_DATA)LSA_ALLOCATE_HEAP(sizeof(SAM_USER_DATA))) == NULL)
	{
		CHECK_STATUS_VAR = STATUS_NO_MEMORY;
		LOG_ERROR(L"Error[0x%08X] allocate out buffer", CHECK_STATUS_VAR);
		return CHECK_STATUS_VAR;
	}

	LOG_TRACE(L"memset ObjectAttributes");
	memset(&ObjectAttributes, NULL, sizeof(ObjectAttributes));

	if (!ARGUMENT_PRESENT(pPolicyDomainInfo))
	{
		LOG_TRACE(L"LsaOpenPolicy");
		if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &hLsaPolicy)))
		{
			LOG_ERROR(L"Error LsaOpenPolicy: 0x%08X\n", CHECK_STATUS_VAR);
			CHECK_STATUS_EXIT();
		}

		LOG_TRACE(L"LsaQueryInformationPolicy");
		if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaQueryInformationPolicy(hLsaPolicy, PolicyLocalAccountDomainInformation, reinterpret_cast<PVOID *>(&pPolicyDomainInfo))))
		{
			LOG_ERROR(L"Error LsaQueryInformationPolicy: 0x%08X\n", CHECK_STATUS_VAR);
			CHECK_STATUS_EXIT();
		}

		LsaClose(hLsaPolicy);
		hLsaPolicy = NULL;
	}	

	/*/// TODO проверки
	pSamUserData->pPolicyDomainInfo = (PPOLICY_ACCOUNT_DOMAIN_INFO)LSA_ALLOCATE_HEAP(sizeof(POLICY_ACCOUNT_DOMAIN_INFO));
	memset(pSamUserData->pPolicyDomainInfo, 0, sizeof(POLICY_ACCOUNT_DOMAIN_INFO));

	pSamUserData->pPolicyDomainInfo->DomainName.Buffer = (LPWSTR)LSA_ALLOCATE_HEAP(MAX_PATH * sizeof(WCHAR));

	wcscpy(pSamUserData->pPolicyDomainInfo->DomainName.Buffer, pwsDomain);
	pSamUserData->pPolicyDomainInfo->DomainName.Length = (USHORT)wcslen(pwsDomain);
	pSamUserData->pPolicyDomainInfo->DomainName.MaximumLength = pSamUserData->pPolicyDomainInfo->DomainName.Length + 1;
*/
	LOG_DEBUG(L"Domain: %s", pPolicyDomainInfo->DomainName.Buffer);
	LOG_TRACE(L"LsaSamConnect");
	if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaSamConnect(NULL, &pSamUserData->hSam, SAM_SERVER_ALL_ACCESS, (POBJECT_ATTRIBUTES)&ObjectAttributes)))
	{
		LOG_ERROR(L"Error SamConnect: 0x%08X\n", CHECK_STATUS_VAR);
		goto Cleanup;
	}

	*pSamTokenHandler = (OEM_SAM_HANDLE)pSamUserData;

	LOG_TRACE(L"Initialize SAM DB successfull");
Cleanup:
	CHECK_STATUS_EXIT();
}

VOID FreeSamDatabase(
	OEM_SAM_HANDLE SamTokenHandler
)
{
	DEFINE_SAM_DATA_CAST(pSamData, SamTokenHandler);

	if (!ARGUMENT_PRESENT(pSamData))
	{
		LOG_DEBUG(L"Handler of SAM DB is NULL. Now going away.");
		return;
	}

	if (ARGUMENT_PRESENT(pSamData->hSam))
	{
		LOG_TRACE(L"LsaSamCloseHandle hSam");
		LsaSamCloseHandle(pSamData->hSam);
	}
	
	if (ARGUMENT_PRESENT(pSamData->hUser))
	{
		LOG_TRACE(L"LsaSamCloseHandle hUser");
		LsaSamCloseHandle(pSamData->hUser);
	}

	LOG_TRACE(L"LSA_FREE_HEAP pSamData");
	LSA_FREE_HEAP(pSamData);
	
	LOG_TRACE(L"SAM database resources cleanup successfull");
}

NTSTATUS NTAPI SetupUserContext(
	_In_ OEM_SAM_HANDLE hSamTokenHandler,
	_In_ LPCWSTR pcwUsername
)
{
	CHECK_STATUS_INIT(STATUS_SUCCESS);
	DEFINE_SAM_DATA_CAST(pSamData, hSamTokenHandler);
	SAM_ENUMERATE_HANDLE				EnumerationContext = 0;
	NTSTATUS							EnumerateStatus;
	PVOID								pbBuffer = NULL;
	ULONG								userDomainCount = 0;

	LOG_FUNCTION_CALL();
	assert(ARGUMENT_PRESENT(hSamTokenHandler));
	assert(ARGUMENT_PRESENT(pSamData));
	assert(ARGUMENT_PRESENT(pcwUsername) && wcslen(pcwUsername) > 0);
	SAM_REQ_FUNCTION_CHECK();

	if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaSamOpenDomain(pSamData->hSam, MAXIMUM_ALLOWED, pPolicyDomainInfo->DomainSid, &pSamData->hDomine)))
	{
		LOG_ERROR(L"Can't open domain [%s]: 0x%08X", pPolicyDomainInfo->DomainName, CHECK_STATUS_VAR);
		goto Cleanup;
	}
			
	LOG_TRACE(L"SamOpenDomain: OK! HANDLE: 0x%16X\n", pSamData->hDomine);
	do {
		EnumerateStatus = LsaSamEnumerateUsersInDomain(pSamData->hDomine, &EnumerationContext, USER_NORMAL_ACCOUNT, (PVOID*)&pbBuffer, 10, &userDomainCount);

		PSAM_RID_ENUMERATION userShortInfo = (PSAM_RID_ENUMERATION)(pbBuffer);
		if (!ARGUMENT_PRESENT(userShortInfo))
		{
			LOG_ERROR(L"SamEnumerateUsersInDomain. index: %hu, status:0x%08X\n", EnumerationContext, CHECK_STATUS_VAR);
			goto Cleanup;
		}
		
		// Целевое условие поиска пользователя в базе данных
		if (0 == wcscmp(userShortInfo->Name.Buffer, pcwUsername))
		{
			PVOID		pbBufferInfo = NULL;
			
			LOG_INFO(L"Select username form SAM DB of RID: %lu", userShortInfo->RelativeId);			
			LOG_DEBUG(L"Enumeration context: %lu\n", EnumerationContext);
			if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaSamOpenUser(pSamData->hDomine, MAXIMUM_ALLOWED, userShortInfo->RelativeId, &pSamData->hUser)))
			{
				LOG_ERROR(L"[0x%16X] Can't open SAM handler of user RID: %lu", userShortInfo->RelativeId, CHECK_STATUS_VAR);
				goto Cleanup;
			}
				
			if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaSamQueryInformationUser(pSamData->hUser, UserAllInformation, &pbBufferInfo)))
			{
				LOG_ERROR(L"[0x%16X] Can't retrieve user information by handler: 0x%16X", pSamData->hUser, CHECK_STATUS_VAR);
							
				goto Cleanup;
			}

			pSamData->pUserAllInformation = (PUSER_ALL_INFORMATION)(pbBufferInfo);
			pSamData->pUserRID = userShortInfo;

			break;
		}
	} while (EnumerateStatus == 0x00000105);

	if (!ARGUMENT_PRESENT(pSamData->pUserAllInformation) || !ARGUMENT_PRESENT(pSamData->pUserRID))
	{
		LOG_ERROR(L"User '%s' not found. Enumeration statu: %lu, Check status: %lu", pcwUsername, EnumerateStatus, CHECK_STATUS_VAR);
		CHECK_STATUS_VAR = STATUS_NO_SUCH_USER;
	}

Cleanup:
	if (!NT_SUCCESS(CHECK_STATUS_VAR))
	{
		LOG_TRACE(L"Function is not success. Cleaning...");
		FreeSamDatabase((OEM_SAM_HANDLE)pSamData);		
	}

	CHECK_STATUS_EXIT();
}


NTSTATUS AllocateInteractiveProfile(
	_In_ PLSA_CLIENT_REQUEST ClientRequest,
	_Out_bytecapcount_(ProfileBufferSize) PVOID *ProfileBuffer,
	_Out_ PULONG ProfileBufferSize,
	_In_ OEM_SAM_HANDLE pSamTokenHandler
)
{
	CHECK_STATUS_INIT(SEC_E_OK);
	DEFINE_SAM_DATA_CAST(pSamData, pSamTokenHandler);
	PMSV1_0_INTERACTIVE_PROFILE		profile;
	//LPBYTE							data;

	SAM_REQ_FUNCTION_CHECK();

	assert(ARGUMENT_PRESENT(pSamData));
	E_CHECK(
		ARGUMENT_PRESENT(pSamData),
		STATUS_NO_MEMORY,
		L"Cant retrieve SAM data from handler"
	);

	*ProfileBufferSize = sizeof(MSV1_0_INTERACTIVE_PROFILE) +
	(
		PSAM_USER(pSamData)->ScriptPath.MaximumLength +
		PSAM_USER(pSamData)->HomeDirectory.MaximumLength +
		PSAM_USER(pSamData)->HomeDirectoryDrive.MaximumLength +
		PSAM_USER(pSamData)->FullName.MaximumLength +
		PSAM_USER(pSamData)->ProfilePath.MaximumLength +
		pPolicyDomainInfo->DomainName.MaximumLength
	) * (ULONG)sizeof(WCHAR);

	E_CHECK(
		ARGUMENT_PRESENT((profile = (PMSV1_0_INTERACTIVE_PROFILE)LSA_ALLOCATE_HEAP(*ProfileBufferSize))),
		STATUS_NO_MEMORY,
		L"Can't allocate profile buffer"
	);

	NT_CHECK_GOTO(
		LSA_ALLOCATE_CLIENT_BUFFER_F(ClientRequest, *ProfileBufferSize, (PVOID*)ProfileBuffer),
		Cleanup,
		L"Allocate ProfileBuffer failed (0x%08X)",
		CHECK_STATUS_VAR
	);

	profile->MessageType = MsV1_0InteractiveProfile;
	profile->LogonCount = (USHORT)PSAM_USER(pSamData)->LogonCount;
	profile->BadPasswordCount = (USHORT)PSAM_USER(pSamData)->BadPasswordCount;

	memcpy_s(&profile->LogonTime, sizeof(LARGE_INTEGER), &PSAM_USER(pSamData)->LastLogon, sizeof(LARGE_INTEGER));
	memcpy_s(&profile->LogoffTime, sizeof(LARGE_INTEGER), &PSAM_USER(pSamData)->LastLogoff, sizeof(LARGE_INTEGER));
	memcpy_s(&profile->KickOffTime, sizeof(LARGE_INTEGER), &PSAM_USER(pSamData)->AccountExpires, sizeof(LARGE_INTEGER));
	
	profile->PasswordLastSet = PSAM_USER(pSamData)->PasswordLastSet;
	profile->PasswordCanChange = PSAM_USER(pSamData)->PasswordCanChange;
	profile->PasswordMustChange = PSAM_USER(pSamData)->PasswordMustChange;

	/*data = (LPBYTE)(profile + sizeof(MSV1_0_INTERACTIVE_PROFILE));
#define CPY_UNICODE_STRING_PROFILE(padding, from, to)						\
	data += padding * sizeof(WCHAR);										\
	profile->to.Buffer = (LPWSTR)data;										\
	wcscpy(profile->to.Buffer, PSAM_USER(pSamData)->from.Buffer);			\
	profile->to.Length = PSAM_USER(pSamData)->from.Length;					\
	profile->to.MaximumLength = PSAM_USER(pSamData)->from.MaximumLength;

	CPY_UNICODE_STRING_PROFILE(1, ScriptPath, LogonScript);
	CPY_UNICODE_STRING_PROFILE(PSAM_USER(pSamData)->ScriptPath.MaximumLength, HomeDirectory, HomeDirectory);
	CPY_UNICODE_STRING_PROFILE(PSAM_USER(pSamData)->HomeDirectory.MaximumLength, HomeDirectoryDrive, HomeDirectoryDrive);
	CPY_UNICODE_STRING_PROFILE(PSAM_USER(pSamData)->HomeDirectoryDrive.MaximumLength, FullName, FullName);
	CPY_UNICODE_STRING_PROFILE(PSAM_USER(pSamData)->FullName.MaximumLength, ProfilePath, ProfilePath);

	data += (PSAM_USER(pSamData)->ProfilePath.MaximumLength) * sizeof(WCHAR);
	profile->LogonServer.Buffer = (LPWSTR)data;
	wcscpy(profile->LogonServer.Buffer, pSamData->pPolicyDomainInfo->DomainName.Buffer);*/

	/// возможно тут надо auth_flags. 
	/// <TODO> выявить назначение поля[auth_flags]</TODO>
	profile->UserFlags = PSAM_USER(pSamData)->WhichFields;

	NT_CHECK_GOTO(
		LSA_COPY_TO_CLIENT_BUFFER_F(ClientRequest, *ProfileBufferSize, (PVOID)*ProfileBuffer, profile),
		Cleanup,
		L"Copy to ProfileBuffer failed (0x%08X)",
		CHECK_STATUS_VAR
	);

	/// <TODO> Копировать </TODO>

	LOG_DEBUG(L"Successfull allocate of profile buffer and copy to client process. Size: %lu", *ProfileBufferSize);

Cleanup:
	if (profile)
	{
		LSA_FREE_HEAP(profile);
	}
	CHECK_STATUS_EXIT();
}

NTSTATUS AllocateTokenInformation(
	OEM_SAM_HANDLE pSamTokenHandler,
	LSA_TOKEN_INFORMATION_TYPE TokenInforamtionType,
	PVOID* TokenInformation
)
{
	CHECK_NTSTATUS_INIT(S_OK);
	DEFINE_SAM_DATA_CAST(pSamData, pSamTokenHandler);

	/*PSID UserSid = NULL, pTmpSid;
	LPGROUP_USERS_INFO_0 GlobalGroups = NULL;
	LPGROUP_USERS_INFO_0 LocalGroups = NULL;
	DWORD NumGlobalGroups = 0, TotalGlobalGroups = 0;
	DWORD NumLocalGroups = 0, TotalLocalGroups = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;
	PTOKEN_PRIVILEGES TokenPrivs = NULL;
	wchar_t grName[256 + 256];*/
	/*int n, j, p, q;
	SID_NAME_USE Use;
	LSA_OBJECT_ATTRIBUTES lsa = { sizeof(LSA_OBJECT_ATTRIBUTES) };
	PUNICODE_STRING lsaUserRights;
	DWORD NumUserRights;
	LSA_HANDLE hLsa = NULL;*/
	SID_IDENTIFIER_AUTHORITY	sIdentityAuthority = SECURITY_NT_AUTHORITY;
	LPBYTE						HeapPtr;
	LPBYTE						HeapBase;
	PTOKEN_GROUPS				pTokenGroups = NULL;
	PGROUP_MEMBERSHIP			pGroupMembership = NULL;
	ULONG						ulMembershipCount = 0;
	DWORD						index;

	//LPCWSTR wszDomain = pSamData->pPolicyDomainInfo->DomainName.Buffer;
	//LPCWSTR wszUser = pSamData->pUserRID->Name.Buffer;

	assert(TokenInforamtionType == LsaTokenInformationV2);
	SAM_REQ_FUNCTION_CHECK();

	PLSA_TOKEN_INFORMATION_V2 TokenInformationV2;

	/*В версии 1 поддерживается только LsaTokenInformationV2 */
	if (TokenInforamtionType == LsaTokenInformationNull
		|| TokenInforamtionType == LsaTokenInformationV3
		|| TokenInforamtionType == LsaTokenInformationV1)
	{
		CHECK_STATUS_VAR = E_NOT_SET;
		goto Cleanup;
	}

	assert(ARGUMENT_PRESENT(pSamTokenHandler));
	assert(ARGUMENT_PRESENT(pSamData));
	if (pSamData == NULL || pSamTokenHandler == NULL)
	{
		CHECK_STATUS_VAR = STATUS_INVALID_PARAMETER;
		goto Cleanup;
	}
	
	TokenInformationV2 = (PLSA_TOKEN_INFORMATION_V2)LSA_ALLOCATE_HEAP(sizeof(LSA_TOKEN_INFORMATION_V2) + HEAP_SIZE);
	if (!*TokenInformation) {
		CHECK_STATUS_VAR = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	HeapPtr = HeapBase = (LPBYTE)(TokenInformationV2 + 1);

	LOG_DEBUG(L"Querying local LSA database\n");
	

	//if (!wszDomain || !wszDomain[0])
	//	wcscpy_s(grName, wcslen(wszUser) + sizeof(WCHAR), wszUser);
	//else
	//	wsprintfW(grName, L"%s\\%s", wszDomain, wszUser); // Used for domain/user clashes

	///* Search on the specified PDC, then on the local domain, for the user.
	///* his allows for trusted domains to work */
	/*if ((CHECK_STATUS_VAR = LookupSid(grName, &UserSid, &Use, &HeapBase, &HeapPtr)) != S_OK || Use != SidTypeUser)
	{
		LOG_DEBUG(L"LookupSid failed (%08x,%d)\n", CHECK_STATUS_VAR, (int)Use);
		CHECK_STATUS_VAR = CHECK_STATUS_VAR ? CHECK_STATUS_VAR : STATUS_NO_SUCH_USER;
		goto Cleanup;
	}*/

	TokenInformationV2->Owner.Owner = NULL;
	TokenInformationV2->User.User.Attributes = 0;
	LsaSamRidToSid(pSamData->hUser, pSamData->pUserRID->RelativeId, &TokenInformationV2->User.User.Sid);

	if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaSamGetGroupsForUser(pSamData->hUser, &pGroupMembership, &ulMembershipCount)))
	{
		LOG_ERROR(L"[0x%16X] Can't retrieve groups for user RID: %lu", pSamData->pUserRID->RelativeId);
		goto Cleanup;
	}
	
	pTokenGroups = (PTOKEN_GROUPS)LsaAllocateHeap(sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)*(ulMembershipCount), &HeapBase, &HeapPtr);
	for (index = 0; index < ulMembershipCount; index++)
	{
		SAM_HANDLE hGroup;
		PGROUP_MEMBERSHIP plGroupMembership = (PGROUP_MEMBERSHIP)(pGroupMembership + index);

		if (!ARGUMENT_PRESENT(plGroupMembership))
		{
			LOG_TRACE(L"Group index %lu not present. skiping..", index);
			continue;
		}

		if (!NT_SUCCESS(CHECK_STATUS_VAR = LsaSamOpenGroup(pSamData->hDomine, GROUP_ALL_ACCESS, plGroupMembership->RelativeId, &hGroup)))
		{
			LOG_WARNING(L"[0x%16X] Can't retrieve groups index %lu for user RID: %lu", index, pSamData->pUserRID->RelativeId);
			continue;
		}

		LsaSamRidToSid(hGroup, plGroupMembership->RelativeId, &pTokenGroups->Groups[index].Sid);
		pTokenGroups->Groups[index].Attributes = plGroupMembership->Attributes;

		LsaSamCloseHandle(hGroup);

		LOG_DEBUG(L"Adding group index: %lu, RID: %lu", index, plGroupMembership->RelativeId);
	}
	pTokenGroups->GroupCount = index;

	for (index = ulMembershipCount; index > 0; index--)
	{
		LOG_TRACE(L"Cleanup group member index: %lu", index);
		PGROUP_MEMBERSHIP plGroupMembership = (PGROUP_MEMBERSHIP)(pGroupMembership + index);
		assert(ARGUMENT_PRESENT(plGroupMembership));
		if (!ARGUMENT_PRESENT(plGroupMembership))
		{
			LOG_TRACE(L"Group index %lu not present. skiping..", index);
			continue;
		}

		LsaFreeMemory(plGroupMembership);
		LOG_TRACE(L"Success cleanup group member index: %lu", index);
	}

	if ((CHECK_STATUS_VAR = GetPrimaryGroup(pSamData, TokenInformationV2->User.User.Sid, &TokenInformationV2->PrimaryGroup.PrimaryGroup, &HeapBase, &HeapPtr)) != S_OK)
	{
		LOG_DEBUG(L"GetPrimaryGroup failed\n");
		goto Cleanup;
	}

	//NetUserGetGroups(wszDomain, wszUser, 0, (LPBYTE*)&GlobalGroups, MAX_PREFERRED_LENGTH, &NumGlobalGroups, &TotalGlobalGroups);
	//NetUserGetLocalGroups(wszDomain, wszUser, 0, 0, (LPBYTE*)&LocalGroups, MAX_PREFERRED_LENGTH, &NumLocalGroups, &TotalLocalGroups);

	//pTokenGroups = (PTOKEN_GROUPS)LsaAllocateHeap(sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES)*(NumGlobalGroups + NumLocalGroups + NumGlobalGroups), &HeapBase, &HeapPtr);
	//if (!pTokenGroups) {
	//	CHECK_STATUS_VAR = STATUS_NO_MEMORY;
	//	goto Cleanup;
	//}
	//pTokenGroups->GroupCount = NumGlobalGroups + NumLocalGroups;

	//j = 0;
	//for (n = 0; n < (int)NumLocalGroups; n++)
	//{
	//	if ((CHECK_STATUS_VAR = LookupSid(LocalGroups[n].grui0_name, &pTmpSid, &Use, &HeapBase, &HeapPtr)) == S_OK && pTmpSid)
	//	{
	//		if (memcmp(GetSidIdentifierAuthority(pTmpSid), &nt, sizeof(nt)) ||
	//			*GetSidSubAuthority(pTmpSid, 0) != SECURITY_BUILTIN_DOMAIN_RID)
	//		{
	//			pTokenGroups->Groups[j].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_RESOURCE;
	//		}
	//		else
	//			pTokenGroups->Groups[j].Attributes = 0;
	//		pTokenGroups->Groups[j].Sid = pTmpSid;
	//		LOG_DEBUG(L"Adding local group (%d) %s\n", j, LocalGroups[n].grui0_name);
	//		j++;
	//	}
	//}

	//for (n = 0; n < (int)NumGlobalGroups; n++)
	//{
	//	if ((CHECK_STATUS_VAR = LookupSid(GlobalGroups[n].grui0_name, &pTmpSid, &Use, &HeapBase, &HeapPtr)) == S_OK && pTmpSid)
	//	{
	//		for (q = 0; q < j; q++)
	//		{
	//			if (!pTokenGroups->Groups[q].Sid)
	//				continue;
	//			if (EqualSid(pTokenGroups->Groups[q].Sid, pTmpSid))
	//				break;
	//		}
	//		if (q == j)
	//		{
	//			if (memcmp(GetSidIdentifierAuthority(pTmpSid), &nt, sizeof(nt)) ||
	//				*GetSidSubAuthority(pTmpSid, 0) != SECURITY_BUILTIN_DOMAIN_RID)
	//			{
	//				pTokenGroups->Groups[j].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
	//			}
	//			else
	//				pTokenGroups->Groups[j].Attributes = 0;
	//			pTokenGroups->Groups[j].Sid = pTmpSid;
	//			LOG_DEBUG(L"Adding global group (%d) %s\n", j, GlobalGroups[n].grui0_name);
	//			j++;
	//		}
	//	}
	//}

	//pTokenGroups->GroupCount = j;
	//LOG_DEBUG(L"Added %d groups\n", j);

	//if ((CHECK_STATUS_VAR = GetPrimaryGroup(wszDomain, wszUser, UserSid, &TokenInformationV2->PrimaryGroup.PrimaryGroup, &HeapBase, &HeapPtr)) != S_OK)
	//{
	//	LOG_DEBUG(L"GetPrimaryGroup failed\n");
	//	goto Cleanup;
	//}

	//j = 0;
	//lsaUserRights = NULL;
	//NumUserRights = 0;
	//if ((CHECK_STATUS_VAR = LsaEnumerateAccountRights(hLsa, UserSid, &lsaUserRights, &NumUserRights)) == S_OK)
	//{
	//	LOG_DEBUG(L"LsaEnumerateAccountRights (user) returned %d rights\n", NumUserRights);
	//	j += NumUserRights;
	//	NetApiBufferFree(lsaUserRights);
	//}
	//else
	//{
	//	if (LsaNtStatusToWinError(CHECK_STATUS_VAR) != 2)
	//		LOG_DEBUG(L"LsaEnumerateAccountRights (user) failed (%08x:%d)\n", CHECK_STATUS_VAR, LsaNtStatusToWinError(CHECK_STATUS_VAR));
	//}

	//for (n = 0; n < (int)pTokenGroups->GroupCount; n++)
	//{
	//	lsaUserRights = NULL;
	//	NumUserRights = 0;
	//	if ((CHECK_STATUS_VAR = LsaEnumerateAccountRights(hLsa, pTokenGroups->Groups[n].Sid, &lsaUserRights, &NumUserRights)) == S_OK)
	//	{
	//		LOG_DEBUG(L"LsaEnumerateAccountRights (group) returned %d rights\n", NumUserRights);
	//		j += NumUserRights;
	//		NetApiBufferFree(lsaUserRights);
	//	}
	//	else
	//	{
	//		if (LsaNtStatusToWinError(CHECK_STATUS_VAR) != 2)
	//			LOG_DEBUG(L"LsaEnumerateAccountRights (group) failed (%08x:%d)\n", CHECK_STATUS_VAR, LsaNtStatusToWinError(CHECK_STATUS_VAR));
	//	}
	//}
	//LOG_DEBUG(L"Possible %d group rights\n", j);

	//TokenPrivs = (PTOKEN_PRIVILEGES)LsaAllocateHeap(sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)*j, &HeapBase, &HeapPtr);
	//if (!TokenPrivs) {
	//	CHECK_STATUS_VAR = STATUS_NO_MEMORY;
	//	goto Cleanup;
	//}
	//TokenPrivs->PrivilegeCount = j;
	//j = 0;
	//if ((CHECK_STATUS_VAR = LsaEnumerateAccountRights(hLsa, UserSid, &lsaUserRights, &NumUserRights)) == S_OK)
	//{
	//	for (n = 0; n < (int)NumUserRights; n++)
	//	{
	//		TokenPrivs->Privileges[j].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
	//		if (!LookupPrivilegeValueW(wszDomain, lsaUserRights[n].Buffer, &TokenPrivs->Privileges[j].Luid))
	//		{
	//			LOG_DEBUG(L"LookupPrivilegeValue(%s) failed (%d)\n", lsaUserRights[n].Buffer, GetLastError());
	//			continue;
	//		}
	//		LOG_DEBUG(L"User: Adding (%d) %s\n", j, lsaUserRights[n].Buffer);
	//		j++;
	//	}
	//	NetApiBufferFree(lsaUserRights);
	//}

	//for (n = 0; n < (int)pTokenGroups->GroupCount; n++)
	//{
	//	if ((CHECK_STATUS_VAR = LsaEnumerateAccountRights(hLsa, pTokenGroups->Groups[n].Sid, &lsaUserRights, &NumUserRights)) == S_OK)
	//	{
	//		for (p = 0; p < (int)NumUserRights; p++)
	//		{
	//			LUID luid;
	//			if (!LookupPrivilegeValueW(wszDomain, lsaUserRights[p].Buffer, &luid))
	//			{
	//				LOG_DEBUG(L"LookupPrivilegeValue(%s) failed (%d)\n", lsaUserRights[p].Buffer, GetLastError());
	//				continue;
	//			}
	//			for (q = 0; q < j; q++)
	//				if (!memcmp(&luid, &TokenPrivs->Privileges[q].Luid, sizeof(luid)))
	//					break;
	//			if (q == j)
	//			{
	//				LOG_DEBUG(L"Group: Adding (%d) %s\n", j, lsaUserRights[p].Buffer);
	//				TokenPrivs->Privileges[j].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
	//				TokenPrivs->Privileges[j].Luid = luid;
	//				j++;
	//			}
	//		}
	//		NetApiBufferFree(lsaUserRights);
	//	}
	//}

	//TokenPrivs->PrivilegeCount = j;
	//LOG_DEBUG(L"Added %d rights\n", j);

	///* Strip out the BUILTIN stuff */
	//for (n = pTokenGroups->GroupCount; n >= 0; --n)
	//{
	//	if (pTokenGroups->Groups[n].Attributes == 0)
	//	{
	//		if ((int)pTokenGroups->GroupCount > n)
	//			memcpy(pTokenGroups->Groups + n, pTokenGroups->Groups + n + 1, sizeof(pTokenGroups->Groups[0])*(pTokenGroups->GroupCount - n));
	//		pTokenGroups->GroupCount--;
	//	}
	//}

	//LOG_DEBUG(L"%d groups after cleanup\n", pTokenGroups->GroupCount);

	TokenInformationV2->Groups = pTokenGroups;
	TokenInformationV2->Privileges = NULL;
	TokenInformationV2->Owner.Owner = NULL;
	TokenInformationV2->DefaultDacl.DefaultDacl = NULL;

	LOG_INFO(L"Allocate toke information buffer V2 is success!");

	*TokenInformation = (PVOID)TokenInformationV2;
	CHECK_STATUS_VAR = S_OK;

Cleanup:
	if (!NT_SUCCESS(CHECK_STATUS_VAR))
	{
		FreeSamDatabase(pSamTokenHandler);
	}
	CHECK_STATUS_EXIT();
}


#pragma region PRIVATE

//static NTSTATUS LookupSid(
//	LPCWSTR szSid,
//	PSID* pUserSid,
//	SID_NAME_USE* Use,
//	LPBYTE * ppHeapBase,
//	LPBYTE * ppHeapPtr
//)
//{
//	DWORD UserSidSize = 0, DomainSize = 0;
//	LPWSTR szDomain;
//
//	*Use = SidTypeInvalid;
//	*pUserSid = NULL;
//
//	LookupAccountNameW(NULL, szSid, NULL, &UserSidSize, NULL, &DomainSize, NULL);
//	if (!UserSidSize)
//	{
//		LOG_DEBUG(L"LookupAccountName(%s) failed pass 1 : no account? (%08x)", szSid, GetLastError());
//		return STATUS_NO_SUCH_USER;
//	}
//
//	*pUserSid = (PSID)LsaAllocateHeap(UserSidSize, ppHeapBase, ppHeapPtr);
//	if (!*pUserSid)
//		return STATUS_NO_MEMORY;
//
//	szDomain = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DomainSize);
//	if (!szDomain)
//		return STATUS_NO_MEMORY;
//
//	if (!LookupAccountNameW(NULL, szSid, *pUserSid, &UserSidSize, szDomain, &DomainSize, Use))
//	{
//		*pUserSid = NULL;
//		LOG_DEBUG(L"LookupAccountName(%s) failed pass 2 : no account? (%08x)", szSid, GetLastError());
//		return STATUS_NO_SUCH_USER;
//	}
//
//	HeapFree(GetProcessHeap(), 0, szDomain);
//
//	return S_OK;
//}
//

static NTSTATUS GetPrimaryGroup(
	_In_ PSAM_USER_DATA pSamData,
	_In_ PSID UserSid,
	_Out_ PSID *PrimarySid,
	_Inout_ LPBYTE *ppHeapBase,
	_Inout_ LPBYTE *ppHeapPtr
)
{
	UCHAR count;
	ULONG size = GetLengthSid(UserSid);

	*PrimarySid = (PSID)LsaAllocateHeap(size, ppHeapBase, ppHeapPtr);
	if (!*PrimarySid)
	{
		return STATUS_NO_MEMORY;
	}
	
	CopySid(size, *PrimarySid, UserSid);
	if (IsValidSid(*PrimarySid) && (count = *GetSidSubAuthorityCount(*PrimarySid)) > 1)
	{
		*GetSidSubAuthority(*PrimarySid, count - 1) = pSamData->pUserAllInformation->PrimaryGroupId;
	}

	return S_OK;
}
#pragma endregion

EXTERN_C_END