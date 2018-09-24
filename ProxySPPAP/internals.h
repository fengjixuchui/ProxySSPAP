#pragma once

#include <Windows.h>
#include "log.h"

/* указатель на таблицу функций */
extern PLSA_SECPKG_FUNCTION_TABLE pLsaDispatch;

/* указатель загружаемый модуль */
extern HMODULE MsvPackage;