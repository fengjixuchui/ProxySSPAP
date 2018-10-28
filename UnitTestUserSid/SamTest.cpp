#include "stdafx.h"
#include <sam.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest
{
	TEST_CLASS(Sam)
	{
		OEM_SAM_HANDLE SamTokenHandler;
	public:

		TEST_METHOD(Initialize)
		{
			Logger::WriteMessage("Тест инициализации SAM DB");
			NTSTATUS Status;
			EXTERN_C_START
			Status = InitSamDatabase(&SamTokenHandler) ;
			EXTERN_C_END
			Assert::AreEqual<NTSTATUS>(STATUS_SUCCESS, Status, L"Не удалось инициализировать соединение с SAM DB");
		}
	};
}