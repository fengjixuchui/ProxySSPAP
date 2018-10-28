// stdafx.h: включаемый файл для стандартных системных включаемых файлов,
// или включаемых файлов для конкретного проекта, которые часто используются, но
// не часто изменяются
//

#pragma once

#include "targetver.h"

// Заголовки CppUnitTest
#include "CppUnitTest.h"
#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
#define SECURITY_WIN32
#define UMDF_USING_NTSTATUS
// Файлы заголовков Windows: Включим определения LSA Security API
#include <windows.h>
EXTERN_C_START
#include <ntstatus.h>
#include <sspi.h>
#include <NTSecAPI.h>
#include <NTSecPKG.h>

EXTERN_C_END

// TODO: Установите здесь ссылки на дополнительные заголовки, требующиеся для программы
