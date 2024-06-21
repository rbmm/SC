#include "stdafx.h"

#pragma code_seg(".text$mn$cpp")

#pragma intrinsic(strcmp, strlen)

#if defined(_X86_)
__inline _TEB* NtCurrentTeb2() { return ( _TEB *) (ULONG_PTR) __readfsdword (PcTeb); }
#elif defined (_AMD64_)
__inline _TEB* NtCurrentTeb2(){ return ( _TEB *)__readgsqword(FIELD_OFFSET(NT_TIB, Self));}
#endif

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"

PVOID GetNtBase()
{
	return CONTAINING_RECORD(NtCurrentTeb2()->ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink,
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

PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName)
{
	CPP_FUNCTION;

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pidh, pidh->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pidh, 
		pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfNames);
	PDWORD AddressOfFunctions = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)RtlOffsetToPointer(pidh, pied->AddressOfNameOrdinals);

	DWORD a = 0, b = pied->NumberOfNames, o;

	if (b) 
	{
		do
		{
			int i = strcmp(ProcedureName, RtlOffsetToPointer(pidh, AddressOfNames[o = (a + b) >> 1]));
			if (!i)
			{
				PVOID pv = RtlOffsetToPointer(pidh, AddressOfFunctions[AddressOfNameOrdinals[o]]);

				if ((ULONG_PTR)pv - (ULONG_PTR)pied < pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					ANSI_STRING as = { (USHORT)strlen(ProcedureName), as.Length, const_cast<PSTR>(ProcedureName) };
					if (0 > LdrGetProcedureAddress((HMODULE)pidh, &as, 0, &pv)) return 0;
				}

				return pv;
			}

			if (0 > i) b = o; else a = o + 1;

		} while (a < b);
	}

	return 0;
}
