#include "stdafx.h"
#include "CppUnitTest.h"
#include <Windows.h>
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest
{		
	TEST_CLASS(User)
	{
	public:
		
		TEST_METHOD(GetSID)
		{
			const DWORD INITIAL_SIZE = 32;
			DWORD cbSid = 0;
			DWORD dwSidBufferSize = INITIAL_SIZE;
			DWORD cchDomainName = 0;
			DWORD dwDomainBufferSize = INITIAL_SIZE;
			WCHAR * wszDomainName = NULL;
			LPCWSTR wszAccName = L"Дампик";
			SID_NAME_USE eSidType;
			DWORD dwErrorCode = 0;
			HRESULT hr = S_OK;
			PSID ppSid;
			// Create buffers for the SID and the domain name.  
			Assert::IsNotNull(ppSid = (PSID) new BYTE[dwSidBufferSize]);
			
			memset(ppSid, 0, dwSidBufferSize);
			Assert::IsNotNull(wszDomainName = new WCHAR[dwDomainBufferSize]);
			memset(wszDomainName, 0, dwDomainBufferSize * sizeof(WCHAR));

			for (;;)
			{
				LookupAccountNameW(
					NULL,            // Computer name. NULL for the local computer  
					wszAccName,
					ppSid,          // Pointer to the SID buffer. Use NULL to get the size needed,  
					&cbSid,          // Size of the SID buffer needed.  
					wszDomainName,   // wszDomainName,  
					&cchDomainName,
					&eSidType
				);
				if (ppSid != NULL)
					break;
			}

			Assert::IsNotNull(ppSid);
		}

	};
}