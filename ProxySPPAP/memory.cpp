#include "stdafx.h"

EXTERN_C_START

#include "internals.h"
#include <logger.h>


LSA_STRING *AllocateLsaStringLsa(
	LPCSTR szString
)
{
	LSA_STRING *s;
	size_t len = strlen(szString);

	s = (LSA_STRING *)LSA_ALLOCATE_HEAP(sizeof(LSA_STRING));
	if (!s)
		return NULL;
	s->Buffer = (char *)LSA_ALLOCATE_HEAP((ULONG)len + 1);
	s->Length = (USHORT)len;
	s->MaximumLength = (USHORT)len + 1;
	strcpy_s(s->Buffer, s->MaximumLength, szString);
	return s;
}

UNICODE_STRING *AllocateUnicodeStringLsa(
	LPCWSTR szString
)
{
	UNICODE_STRING *s;
	size_t len = wcslen(szString) * sizeof(wchar_t);

	s = (UNICODE_STRING *)LSA_ALLOCATE_HEAP((ULONG)sizeof(UNICODE_STRING));
	if (!s)
		return NULL;
	s->Buffer = (wchar_t *)LSA_ALLOCATE_HEAP((ULONG)len + (ULONG)sizeof(wchar_t));
	s->Length = (USHORT)len;
	s->MaximumLength = (USHORT)len + sizeof(wchar_t);
	wcscpy_s(s->Buffer, s->MaximumLength, szString);
	return s;
}

LPVOID LsaAllocateHeap(
	ULONG size,
	LPBYTE * ppHeapBase,
	LPBYTE * ppHeapPtr
)
{
	LPVOID p;

	if (*ppHeapPtr + size > *ppHeapBase + HEAP_SIZE)
	{
		LOG_DEBUG(L"Out of reserved heap space.  Increase HEAP_SIZE and recompile.");
		return NULL;
	}
	p = *ppHeapPtr;
	*ppHeapPtr += size;
	LOG_DEBUG(L"LsaAllocateHeap(%d) - Heapsize %d\n", size, *ppHeapPtr - *ppHeapBase);
	return p;
}
EXTERN_C_END