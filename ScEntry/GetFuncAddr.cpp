#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"

unsigned long __cdecl istrlen(const char*)ASM_FUNCTION;
char __cdecl istrcmp(const char*, const char*)ASM_FUNCTION;

PVOID GetNtBase()
{
	return CONTAINING_RECORD(NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink,
		_LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)->DllBase;
}

PVOID __fastcall get_hmod(PCWSTR pwz)
{
	CPP_FUNCTION;

	if (*pwz)
	{
		PVOID hmod;
		UNICODE_STRING us;
		RtlInitUnicodeString(&us, pwz);
		return 0 > LdrLoadDll(0, 0, &us, &hmod) ? 0 : hmod;
	}

	return GetNtBase();
}

ULONG StrToInt(PCSTR psz)
{
	ULONG i = 0;
	while (ULONG c = *psz++)
	{
		if ((c -= '0') > 9) return 0;
		i = 10 * i + c;
	}
	return i;
}

PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName)
{
	CPP_FUNCTION;

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pidh, pidh->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pidh, 
		pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	DWORD a = 0, b = pied->NumberOfNames, o;

	if (b) 
	{
		if ('#' == *ProcedureName)
		{
			o = StrToInt(ProcedureName + 1);
			if ((o -= pied->Base) < pied->NumberOfFunctions)
			{
			__index:
				PVOID pv = RtlOffsetToPointer(pidh, ((PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfFunctions))[o]);

				if ((ULONG_PTR)pv - (ULONG_PTR)pied < pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					ANSI_STRING as = { (USHORT)istrlen(ProcedureName), as.Length, const_cast<PSTR>(ProcedureName) };
					if (0 > LdrGetProcedureAddress((HMODULE)pidh, &as, 0, &pv)) return 0;
				}

				return pv;
			}

			__debugbreak();
			return 0;
		}

		PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfNames);

		do
		{
			__int8 i = istrcmp(ProcedureName, RtlOffsetToPointer(pidh, AddressOfNames[o = (a + b) >> 1]));
			if (!i)
			{
				o = ((PWORD)RtlOffsetToPointer(pidh, pied->AddressOfNameOrdinals))[o];
				goto __index;
			}

			0 > i ? b = o : a = o + 1;

		} while (a < b);
	}

	return 0;
}
