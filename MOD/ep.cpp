#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/asmfunc.h"

void NTAPI OnApc(_In_ ULONG rva, _In_ ULONG v, _In_ PVOID ImageBase)
{
	CPP_FUNCTION;

	ULONG f = 0;
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"kdcsvc.dll");
	if (0 <= LdrGetDllHandle(0, &f, &name, &ImageBase))
	{
		*(ULONG*)RtlOffsetToPointer(ImageBase, rva) = v;
	}
}

