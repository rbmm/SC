#include "stdafx.h"

NTSTATUS FindNoCfgDll(_In_ ULONG Machine, _In_ ULONG Magic, _In_ ULONG SizeOfImage, _Out_ PHANDLE SectionHandle);

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
		PIMAGE_BASE_RELOCATION pibr;
		PIMAGE_NT_HEADERS pinth;
		PIMAGE_NT_HEADERS32 pinth32;
		PIMAGE_NT_HEADERS64 pinth64;
	};

	LONG_PTR Delta = 0;

	pinth = RtlImageNtHeader(BaseAddress);

	switch (pinth->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		pv = &pinth32->OptionalHeader.ImageBase;
		Delta = RemoteBase - *(ULONG*)pv;
		*(ULONG*)pv = (ULONG)RemoteBase;
		break;

	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		pv = &pinth64->OptionalHeader.ImageBase;
		Delta = RemoteBase - *(ULONG64*)pv;
		*(ULONG64*)pv = RemoteBase;
		break;
	}

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

NTSTATUS WINAPI GetWowContext( _In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context)
{
	return ZwQueryInformationThread(ThreadHandle, ThreadWow64Context, Context, sizeof(WOW64_CONTEXT), 0);
}

NTSTATUS WINAPI SetWowContext( _In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context)
{
	return ZwSetInformationThread(ThreadHandle, ThreadWow64Context, Context, sizeof(WOW64_CONTEXT));
}

#define CONTEXT_i386 0x00010000L

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"

BOOL Exec(PVOID BaseOfImage, HANDLE hProcess, HANDLE hThread)
{
	CPP_FUNCTION;
	PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(BaseOfImage);

	if (!pinth) return FALSE;

	ULONG SizeOfImage = 0;
	ULONG SizeOfHeaders = 0;
	BOOL b32;
	union {
		CONTEXT ctx {};
		WOW64_CONTEXT wctx;
	};

	NTSTATUS (WINAPI * GetCtx)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context) = 0;
	NTSTATUS (WINAPI * SetCtx)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context) = 0;

	switch (pinth->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS32>(pinth)->OptionalHeader.SizeOfImage;
		SizeOfHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(pinth)->OptionalHeader.SizeOfHeaders;
		wctx.ContextFlags = (CONTEXT_INTEGER & ~CONTEXT_AMD64)|CONTEXT_i386;
		GetCtx = GetWowContext;
		SetCtx = SetWowContext;
		b32 = TRUE;
		break;

	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS64>(pinth)->OptionalHeader.SizeOfImage;
		SizeOfHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(pinth)->OptionalHeader.SizeOfHeaders;
		ctx.ContextFlags = CONTEXT_INTEGER;
		GetCtx = ZwGetContextThread;
		SetCtx = ZwSetContextThread;
		b32 = FALSE;
		break;

	default: return FALSE;
	}

	BOOL fOk = FALSE;
	HANDLE hSection;

	if (0 <= FindNoCfgDll(pinth->FileHeader.Machine, pinth->OptionalHeader.Magic, SizeOfImage, &hSection))
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

				PROCESS_BASIC_INFORMATION pbi;
				PEB32* wow;

				PVOID RemoteBase = 0;
				ViewSize = SizeOfImage;

				if (0 <= NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0) &&
					0 <= NtQueryInformationProcess(hProcess, ProcessWow64Information, &wow, sizeof(wow), 0) &&
					0 <= GetCtx(hThread, &ctx) &&
					0 <= ZwMapViewOfSection(hSection, hProcess, &RemoteBase, 0, 0, 0, &ViewSize, ViewShare, 0, PAGE_READONLY))
				{
					Relocate(BaseAddress, (LONG_PTR)RemoteBase);

					ULONG_PTR AddressOfEntryPoint = (ULONG_PTR)RemoteBase + pinth->OptionalHeader.AddressOfEntryPoint;

					if (b32)
					{
						wctx.Eax = (ULONG)AddressOfEntryPoint;
					}
					else
					{
						ctx.Rcx = AddressOfEntryPoint;
					}

					fOk = 0 <= ZwProtectVirtualMemory(hProcess, &(pv = RemoteBase), &(RegionSize = SizeOfImage), PAGE_READWRITE, &op) &&
						0 <= ZwWriteVirtualMemory(hProcess, RemoteBase, BaseAddress, SizeOfImage, 0) &&
						0 <= ProtectImage(hProcess, RemoteBase, pinth) &&
						0 <= ZwWriteVirtualMemory(hProcess, &reinterpret_cast<PEB*>(pbi.PebBaseAddress)->ImageBaseAddress, &RemoteBase, sizeof(RemoteBase), 0) &&
						0 <= (wow ? ZwWriteVirtualMemory(hProcess, &wow->ImageBaseAddress, &RemoteBase, sizeof(ULONG), 0) : 0) &&
						0 <= SetCtx(hThread, &ctx) &&
						0 <= ZwResumeThread(hThread, 0);
				}
			}
		}

		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
		NtClose(hSection);
	}

	return fOk;
}
