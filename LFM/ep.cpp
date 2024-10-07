#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/asmfunc.h"

#pragma intrinsic(strcmp, strlen)

PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName);
PVOID GetNtBase();

#ifdef _X86_

PCWSTR getSystem32()ASM_FUNCTION;
PCWSTR getSyswow64()ASM_FUNCTION;

PCWSTR getDll()ASM_FUNCTION;

PCSTR GetMapViewOfSection()ASM_FUNCTION;

#else

PCWSTR getSystem32()
{
	return L"\\system32\\";
}

PCWSTR getDll()
{
	return L"*.dll";
}

PCSTR GetMapViewOfSection()
{
	return "ZwMapViewOfSection";
}

#endif // _X86_

//int __cdecl strcmp(const char* src, const char* dst)
//{
//	for (;;++src, ++dst)
//	{
//		ULONG a = *(unsigned char*)src, b = *(unsigned char*)dst;
//		if (int ret = a - b)
//		{
//			return ret;
//		}
//		if (!a) return 0;
//	}
//}

BOOLEAN IsImageOk(_In_ ULONG SizeOfImage, _In_ HANDLE hSection)
{
	BOOLEAN fOk = FALSE;

	SIZE_T ViewSize = 0;
	union {
		PVOID BaseAddress = 0;
		PIMAGE_DOS_HEADER pidh;
	};

	if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, 
		&ViewSize, ViewUnmap, 0, PAGE_READONLY))
	{
		if (ViewSize >= SizeOfImage && pidh->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG VirtualAddress = pidh->e_lfanew;

			if (VirtualAddress < ViewSize - sizeof(IMAGE_NT_HEADERS))
			{
				union {
					PVOID pv;
					PIMAGE_NT_HEADERS pinth;
					PIMAGE_LOAD_CONFIG_DIRECTORY picd;
				};

				pv = RtlOffsetToPointer(BaseAddress, VirtualAddress);
				PIMAGE_SECTION_HEADER pish = 0;
				DWORD NumberOfSections = 0;

				if (pinth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC && 
					pinth->OptionalHeader.SizeOfImage >= SizeOfImage)
				{
					if (NumberOfSections = pinth->FileHeader.NumberOfSections)
					{
						pish = IMAGE_FIRST_SECTION(pinth);
					}

					IMAGE_DATA_DIRECTORY DataDirectory = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

					if (!DataDirectory.VirtualAddress)
					{
						fOk = TRUE;
					}
					else
					{
						if (DataDirectory.VirtualAddress < ViewSize - sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
						{
							pv = RtlOffsetToPointer(BaseAddress, DataDirectory.VirtualAddress);

							fOk = picd->Size < __builtin_offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) || 
								!picd->GuardCFFunctionCount;
						}
					}

					if (fOk)
					{
						if (pish)
						{
							VirtualAddress = (pinth->OptionalHeader.SizeOfHeaders + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
							do
							{
								DWORD VirtualSize = pish->Misc.VirtualSize;

								if (!VirtualSize)
								{
									continue;
								}

								if (VirtualAddress != pish->VirtualAddress)
								{
									fOk = FALSE;
									break;
								}

								VirtualAddress += VirtualSize + PAGE_SIZE - 1;

								VirtualAddress &= ~(PAGE_SIZE - 1);

							} while (pish++, --NumberOfSections);
						}
						else
						{
							fOk = FALSE;
						}
					}
				}
			}
		}

		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	}

	return fOk;
}

NTSTATUS FindNoCfgDll(_In_ ULONG SizeOfImage, _Inout_ PUNICODE_STRING FileName)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(FileName->Buffer, &ObjectName, 0, 0);

	if (0 <= status)
	{
		status = NtOpenFile(&oa.RootDirectory,
			FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ,
			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

		RtlFreeUnicodeString(&ObjectName);
	}

	if (0 <= status)
	{
		status = STATUS_NO_MEMORY;

		enum { buf_size = 0x10000 };

		PVOID ProcessHeap = RtlGetCurrentPeb()->ProcessHeap;

		if (PVOID buf = RtlAllocateHeap(ProcessHeap, 0, buf_size))
		{
			UNICODE_STRING DLL;
			RtlInitUnicodeString(&DLL, getDll());

			while (0 <= (status = NtQueryDirectoryFile(oa.RootDirectory,
				0, 0, 0, &iosb, buf, buf_size, FileDirectoryInformation,
				FALSE, const_cast<PUNICODE_STRING>(&DLL), FALSE)))
			{
				union {
					PVOID pv;
					PUCHAR pc;
					PFILE_DIRECTORY_INFORMATION pfdi;
				};

				pv = buf;

				ULONG NextEntryOffset = 0;

				do
				{
					pc += NextEntryOffset;

					if (pfdi->EndOfFile.QuadPart >= SizeOfImage)
					{
						ObjectName.Buffer = pfdi->FileName;
						ObjectName.MaximumLength = ObjectName.Length = (USHORT)pfdi->FileNameLength;

						PVOID hmod;
						if (STATUS_DLL_NOT_FOUND != LdrGetDllHandle(0, 0, &ObjectName, &hmod))
						{
							// dll with such name already loaded
							continue;
						}

						if (0 <= NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT))
						{
							BOOLEAN fOk = FALSE;

							HANDLE hSection;

							if (0 <= NtCreateSection(&hSection, SECTION_MAP_READ, 0, 0, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile))
							{
								fOk = IsImageOk(SizeOfImage, hSection);

								NtClose(hSection);
							}

							NtClose(hFile);

							if (0 <= status)
							{
								if (fOk)
								{
									//DbgPrint("%I64x %wZ\n", pfdi->EndOfFile.QuadPart, &ObjectName);
									status = RtlAppendUnicodeStringToString(FileName, &ObjectName);

									goto __exit;
								}
							}
						}
					}

				} while (NextEntryOffset = pfdi->NextEntryOffset);
			}
		__exit:

			RtlFreeHeap(ProcessHeap, 0, buf);
		}

		NtClose(oa.RootDirectory);
	}

	return status;
}

struct IMAGE_Ctx : public TEB_ACTIVE_FRAME
{
	PIMAGE_NT_HEADERS _M_pinth;
	PVOID _M_retAddr = 0, _M_pvImage, * _M_pBaseAddress = 0;
	PCUNICODE_STRING _M_lpFileName;
	NTSTATUS _M_status = STATUS_UNSUCCESSFUL;

	IMAGE_Ctx(PTEB_ACTIVE_FRAME_CONTEXT FrameContext,
		PVOID pvImage, PIMAGE_NT_HEADERS pinth, PCUNICODE_STRING lpFileName)
		: _M_pvImage(pvImage), _M_pinth(pinth), _M_lpFileName(lpFileName)
	{
		FrameContext->Flags = 0;
		FrameContext->FrameName = GetMapViewOfSection();
		Context = FrameContext;
		Flags = 0;
		RtlPushFrame(this);
	}

	~IMAGE_Ctx()
	{
		RtlPopFrame(this);
	}

	static IMAGE_Ctx* get()
	{
		if (TEB_ACTIVE_FRAME* frame = RtlGetFrame())
		{
			do
			{
				if (GetMapViewOfSection() == frame->Context->FrameName)
				{
					return static_cast<IMAGE_Ctx*>(frame);
				}
			} while (frame = frame->Previous);
		}

		return 0;
	}
};

NTSTATUS Protect(PVOID VirtualAddress, SIZE_T RegionSize, ULONG NewProtect)
{
	return ZwProtectVirtualMemory(NtCurrentProcess(), &VirtualAddress, &RegionSize, NewProtect, &NewProtect);
}

NTSTATUS OverwriteSection(_In_ PVOID BaseAddress, _In_ PVOID pvImage, _In_ PIMAGE_NT_HEADERS pinth)
{
	ULONG cb = pinth->OptionalHeader.SizeOfHeaders, VirtualSize, SizeOfRawData;
	PVOID VirtualAddress;

	NTSTATUS status;
	if (0 > (status = Protect(BaseAddress, cb, PAGE_READWRITE)))
	{
		return status;
	}

	memcpy(BaseAddress, pvImage, cb);

	Protect(BaseAddress, cb, PAGE_READONLY);

	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do
		{
			if (VirtualSize = pish->Misc.VirtualSize)
			{
				VirtualAddress = RtlOffsetToPointer(BaseAddress, pish->VirtualAddress);

				ULONG Characteristics = pish->Characteristics;

				if (0 > (status = Protect(VirtualAddress, VirtualSize,
					Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE)))
				{
					return status;
				}

				if (cb = min(VirtualSize, SizeOfRawData = pish->SizeOfRawData))
				{
					memcpy(VirtualAddress, RtlOffsetToPointer(pvImage, pish->PointerToRawData), cb);
				}

				if (SizeOfRawData < VirtualSize)
				{
					RtlZeroMemory(RtlOffsetToPointer(VirtualAddress, cb), VirtualSize - SizeOfRawData);
				}

				if (!(Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					if (0 > (status = Protect(VirtualAddress, VirtualSize,
						Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READONLY)))
					{
						return status;
					}
				}
			}

		} while (pish++, --NumberOfSections);
	}

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall retFromMapViewOfSection(NTSTATUS status)
{
	CPP_FUNCTION;

	if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
	{
		*(void**)_AddressOfReturnAddress() = ctx->_M_retAddr;

		if (0 <= status)
		{
			PVOID BaseAddress = *ctx->_M_pBaseAddress;

			PIMAGE_NT_HEADERS pinth = ctx->_M_pinth;

			if (0 <= (status = OverwriteSection(BaseAddress, ctx->_M_pvImage, pinth)))
			{
				if (BaseAddress != (PVOID)pinth->OptionalHeader.ImageBase)
				{
					status = STATUS_IMAGE_NOT_AT_BASE;
				}
			}

			if (0 > status)
			{
				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

				*ctx->_M_pBaseAddress = 0;
			}
		}

		ctx->_M_status = status;
	}

	return status;
}

PVOID retFromMapViewOfSectionAddr()ASM_FUNCTION;

PVECTORED_EXCEPTION_HANDLER aMyVexHandler()ASM_FUNCTION;

LONG NTAPI MyVexHandler(::PEXCEPTION_POINTERS ExceptionInfo)
{
	CPP_FUNCTION;
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
	::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

	if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == (PVOID)ContextRecord->Dr3)
	{
		if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
		{
			UNICODE_STRING ObjectName;
			RtlInitUnicodeString(&ObjectName, (PCWSTR)reinterpret_cast<PNT_TIB>(NtCurrentTeb())->ArbitraryUserPointer);
			if (RtlEqualUnicodeString(&ObjectName, ctx->_M_lpFileName, TRUE))
			{
				ctx->_M_pBaseAddress =
#ifdef _WIN64
				(void**)ContextRecord->R8;

#define SP Rsp
#else
#define SP Esp
				((void***)ContextRecord->Esp)[3];
#endif

				* (PSIZE_T)((void**)ContextRecord->SP)[7] = ctx->_M_pinth->OptionalHeader.SizeOfImage;

				ctx->_M_retAddr = ((void**)ContextRecord->SP)[0];

				((void**)ContextRecord->SP)[0] = retFromMapViewOfSectionAddr();
			}
		}

		ContextRecord->EFlags |= 0x10000;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS LoadLibraryFromMem(
	_Out_ void** phmod,
	_In_ PVOID pvImage,
	_In_ PIMAGE_NT_HEADERS pinth,
	_In_ PCUNICODE_STRING lpFileName)
{
	GUID RtlpAddVectoredHandler = { 0x1FC98BCA, 0x1BA9, 0x4397, { 0x93, 0xF9, 0x34, 0x9E, 0xAD, 0x41, 0xE0, 0x57 } };

	ULONG_PTR OldValue;
	RtlSetProtectedPolicy(&RtlpAddVectoredHandler, 0, &OldValue);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (PVOID VectoredHandlerHandle = RtlAddVectoredExceptionHandler(TRUE, aMyVexHandler()))
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ctx.Dr3 = (ULONG_PTR)GetFuncAddressEx((PIMAGE_DOS_HEADER)GetNtBase(), GetMapViewOfSection());
		ctx.Dr7 = 0x440;

		if (0 <= (status = ZwSetContextThread(NtCurrentThread(), &ctx)))
		{
			TEB_ACTIVE_FRAME_CONTEXT FrameContext;
			IMAGE_Ctx ictx(&FrameContext, pvImage, pinth, lpFileName);

			status = LdrLoadDll(0, 0, const_cast<PUNICODE_STRING>(lpFileName), phmod);

			ctx.Dr3 = 0;
			ctx.Dr7 = 0x400;
			ZwSetContextThread(NtCurrentThread(), &ctx);

			if (0 <= status && (0 > ictx._M_status || !ictx._M_pBaseAddress || *ictx._M_pBaseAddress != *phmod))
			{
				if (0 > ictx._M_status)
				{
					status = ictx._M_status;
				}
				else
				{
					status = STATUS_UNSUCCESSFUL;
				}

				LdrUnloadDll(*phmod);
			}
		}

		RtlRemoveVectoredExceptionHandler(VectoredHandlerHandle);
	}

	if (OldValue) RtlSetProtectedPolicy(&RtlpAddVectoredHandler, OldValue, &OldValue);

	return status;
}

void NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_ PVOID, _In_ PVOID)
{
	CPP_FUNCTION;

	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(pvImage))
	{
		RtlWow64EnableFsRedirection(TRUE);
		WCHAR FileName[0x180];
		UNICODE_STRING ObjectName = { 0, sizeof(FileName), FileName };

		if (0 <= (RtlAppendUnicodeToString(&ObjectName, RtlGetNtSystemRoot())) &&
			0 <= (RtlAppendUnicodeToString(&ObjectName, getSystem32())) &&
			0 <= (FindNoCfgDll(pinth->OptionalHeader.SizeOfImage, &ObjectName)))
		{
			LoadLibraryFromMem(&pvImage, pvImage, pinth, &ObjectName);
		}
	}
}

