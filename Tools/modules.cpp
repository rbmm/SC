#include "stdafx.h"

#include "print.h"
#include "wow.h"

BOOLEAN IsExportSuppressionEnabled(HANDLE hProcess);
NTSTATUS SetExportValid(HANDLE hProcess, LPCVOID pv1, LPCVOID pv2);

typedef struct RTL_PROCESS_MODULE_INFORMATION32 {
	ULONG Section;                 // Not filled in
	ULONG MappedBase;
	ULONG ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR  FullPathName[256];
} *PRTL_PROCESS_MODULE_INFORMATION32;

typedef struct RTL_PROCESS_MODULES32 {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION32 Modules[];
} *PRTL_PROCESS_MODULES32;


/*
 *	List modules for a specific pid (i.e --pid 1234)
*/

PVOID __fastcall get_hmod(PCWSTR pwz);
PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName);

NTSTATUS DoQuery(
				 _In_ HANDLE hProcess,
				 _In_ PVOID RemoteBaseAddress,
				 _In_ ULONG Size,
				 _In_ BOOLEAN ExportSuppression,
				 _In_ FUNC funcs[])
{
	PVOID pvLdrQueryProcessModuleInformation;
	PVOID pvRtlExitUserThread;
	NTSTATUS (NTAPI *QueueApcThread)(HANDLE hThread, PPS_APC_ROUTINE, PVOID , PVOID , PVOID );

	if (funcs)
	{
		pvRtlExitUserThread = funcs[0].pfn;
		pvLdrQueryProcessModuleInformation = funcs[1].pfn;
		QueueApcThread = RtlQueueApcWow64Thread;
	}
	else
	{
		PIMAGE_DOS_HEADER hmod = (PIMAGE_DOS_HEADER)get_hmod(L"");
		pvLdrQueryProcessModuleInformation = GetFuncAddressEx(hmod, "LdrQueryProcessModuleInformation");
		pvRtlExitUserThread = GetFuncAddressEx(hmod, "RtlExitUserThread");
		QueueApcThread = ZwQueueApcThread;
	}

	NTSTATUS status;

	if (ExportSuppression)
	{
		if (0 > (status = SetExportValid(hProcess, pvLdrQueryProcessModuleInformation, pvRtlExitUserThread)))
		{
			return status;
		}
	}

	HANDLE hThread;
	if (0 <= (status = RtlCreateUserThread(hProcess, 0, TRUE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)pvRtlExitUserThread, 0, &hThread, 0)))
	{
		if (0 <= (status = QueueApcThread(hThread, 
			(PPS_APC_ROUTINE)pvLdrQueryProcessModuleInformation,
			RemoteBaseAddress, 
			(PVOID)(ULONG_PTR)Size, 
			(PBYTE)RemoteBaseAddress + Size)))
		{
			NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);

			if (0 <= (status = ZwResumeThread(hThread, 0)))
			{
				LARGE_INTEGER time = { (ULONG)-20000000, -1 };
				status = ZwWaitForSingleObject(hThread, FALSE, &time);
				NtClose(hThread);

				return STATUS_SUCCESS;
			}
		}

		ZwTerminateThread(hThread, 0);
		NtClose(hThread);
	}

	return status;
}

template<typename T>
void DumpM(T* Module, ULONG NumberOfModules)
{
	do 
	{
		DbgPrint("%p %08x \"%hs\"\r\n", Module->ImageBase, Module->ImageSize, Module->FullPathName);

	} while (Module++, --NumberOfModules);
}

void DumpModules(HANDLE hSection, ULONG ofs, BOOLEAN bWow)
{
	union {
		PVOID BaseAddress = 0;
		PRTL_PROCESS_MODULES Modules;
		PRTL_PROCESS_MODULES32 Modules32;
	};

	SIZE_T ViewSize = 0;

	if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 
		0, 0, 0, &ViewSize, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE))
	{
		if (ULONG NumberOfModules = Modules->NumberOfModules)
		{
			if (ULONG size = *(ULONG*)RtlOffsetToPointer(BaseAddress, ofs))
			{
				DbgPrint("DumpModules(w=%x, n=%x, s=%x)\r\n", bWow, NumberOfModules, size);

				if (bWow)
				{
					if (size == offsetof(RTL_PROCESS_MODULES32, Modules[NumberOfModules]))
					{
						DumpM(Modules32->Modules, NumberOfModules);
					}
				}
				else
				{
					if (size == offsetof(RTL_PROCESS_MODULES, Modules[NumberOfModules]))
					{
						DumpM(Modules->Modules, NumberOfModules);
					}
				}
			}
		}

		ZwUnmapViewOfSection(hSection, BaseAddress);
	}
}

NTSTATUS ProQuery(ULONG_PTR dwProcessId)
{
	CLIENT_ID cid = { (HANDLE)dwProcessId };
	HANDLE hProcess;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	NTSTATUS status = NtOpenProcess(&hProcess, 
		PROCESS_VM_OPERATION|
		PROCESS_CREATE_THREAD|
		PROCESS_QUERY_INFORMATION|
		PROCESS_SET_INFORMATION, &oa, &cid);

	if (0 <= status)
	{
		PROCESS_EXTENDED_BASIC_INFORMATION pebi = { sizeof(pebi) };

		if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), 0)))
		{
			if (pebi.IsProcessDeleting)
			{
				status = STATUS_PROCESS_IS_TERMINATING;
			}
			else if (pebi.IsFrozen && pebi.IsStronglyNamed)
			{
				status = STATUS_INVALID_DEVICE_STATE;
			}
			else
			{
				HANDLE hSection;
				enum { secsize = 0x100000 - sizeof(ULONG) };
				LARGE_INTEGER SectionSize = { secsize + sizeof(ULONG) };
				if (0 <= (status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, &SectionSize, PAGE_READWRITE, SEC_COMMIT, 0)))
				{
					PVOID BaseAddress = 0;
					SIZE_T ViewSize = 0;
					if (0 <= (status = ZwMapViewOfSection(hSection, hProcess, &BaseAddress, 
						0, 0, 0, &ViewSize, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE)))
					{
						BOOLEAN ExportSuppression = IsExportSuppressionEnabled(hProcess);

						if (pebi.IsWow64Process)
						{
							FUNC fn[] = { 
								{"RtlExitUserThread"}, 
								{"LdrQueryProcessModuleInformation"},
							};

							if (status = GetWowInfo(fn, _countof(fn)))
							{
								DbgPrint("GetWowInfo=%x\r\n", status);
							}
							else
							{
								switch(status = DoQuery(hProcess, BaseAddress, secsize, ExportSuppression, fn))
								{
								case STATUS_SUCCESS:
									DumpModules(hSection, secsize, TRUE);
									break;
								}
							}
						}

						status = DoQuery(hProcess, BaseAddress, secsize, ExportSuppression, 0);

						ZwUnmapViewOfSection(hProcess, BaseAddress);
					}

					if (0 <= status)
					{
						DumpModules(hSection, secsize, FALSE);
					}

					NtClose(hSection);
				}
			}
		}

		NtClose(hProcess);
	}

	DbgPrint("ProQuery(%u)=%x\r\n", dwProcessId, status);

	if (status)
	{
		PrintError(HRESULT_FROM_NT(status));
	}

	return status;
}
