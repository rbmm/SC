#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/asmfunc.h"

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
				VirtualAddress = (pinth->OptionalHeader.SizeOfHeaders + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

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

		if (0 <= status)
		{
			status = STATUS_NO_MEMORY;

			enum { buf_size = 0x10000 };

			PVOID ProcessHeap = RtlGetCurrentPeb()->ProcessHeap;

			if (PVOID buf = RtlAllocateHeap(ProcessHeap, 0, buf_size))
			{
				static const UNICODE_STRING DLL = RTL_CONSTANT_STRING(L"*.dll");

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
	}

	return status;
}

struct IMAGE_Ctx : TEB_ACTIVE_FRAME, TEB_ACTIVE_FRAME_CONTEXT
{
	PIMAGE_NT_HEADERS _M_pinth;
	PVOID _M_retAddr = 0, _M_pvImage, * _M_pBaseAddress = 0;
	PCUNICODE_STRING _M_lpFileName;
	NTSTATUS _M_status = STATUS_UNSUCCESSFUL;

	IMAGE_Ctx(PVOID pvImage, PIMAGE_NT_HEADERS pinth, PCUNICODE_STRING lpFileName)
		: _M_pvImage(pvImage), _M_pinth(pinth), _M_lpFileName(lpFileName)
	{
		TEB_ACTIVE_FRAME::Flags = 0;
		TEB_ACTIVE_FRAME_CONTEXT::Flags = 0;
		FrameName = "ZwMapViewOfSection";
		Context = this;
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
				if (!strcmp("ZwMapViewOfSection", frame->Context->FrameName))
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

NTSTATUS aretFromMapViewOfSection()ASM_FUNCTION;

LONG NTAPI MyVexHandler(::PEXCEPTION_POINTERS ExceptionInfo)
{
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
	::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

	if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == (PVOID)ContextRecord->Dr3)
	{
		if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
		{
			UNICODE_STRING ObjectName;
			RtlInitUnicodeString(&ObjectName, (PCWSTR)reinterpret_cast<PNT_TIB>(NtCurrentTeb())->ArbitraryUserPointer);
			if (RtlEqualUnicodeString(&ObjectName, ctx->_M_lpFileName, FALSE))
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

				((void**)ContextRecord->SP)[0] = aretFromMapViewOfSection;
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
	struct __declspec(uuid("1FC98BCA-1BA9-4397-93F9-349EAD41E057")) RtlpAddVectoredHandler;

	ULONG_PTR OldValue;
	RtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), 0, &OldValue);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (PVOID VectoredHandlerHandle = RtlAddVectoredExceptionHandler(TRUE, MyVexHandler))
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ctx.Dr3 = (ULONG_PTR)GetProcAddress(GetModuleHandleW(L"ntdll"), "ZwMapViewOfSection");
		ctx.Dr7 = 0x440;

		if (0 <= (status = ZwSetContextThread(NtCurrentThread(), &ctx)))
		{
			IMAGE_Ctx ictx(pvImage, pinth, lpFileName);

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

	if (OldValue) RtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), OldValue, &OldValue);

	return status;
}

struct DSC {
	PVOID ImageBase;
	ULONG TimeDateStamp;
};

VOID NTAPI CheckModule(
	_In_ PLDR_DATA_TABLE_ENTRY ModuleInformation,
	_In_ DSC* Parameter,
	_Out_ BOOLEAN* Stop
)
{
	if (ModuleInformation->TimeDateStamp == Parameter->TimeDateStamp)
	{
		if (0 <= LdrAddRefDll(0, ModuleInformation->DllBase))
		{
			Parameter->ImageBase = ModuleInformation->DllBase;
			*Stop = TRUE;
		}
	}
}

NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ ULONG_PTR Size, _Out_opt_ void** ppv)
{
	NTSTATUS status;

	PIMAGE_NT_HEADERS pinth;

	if (0 <= (status = RtlImageNtHeaderEx(Size ? 0 : RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, pvImage, Size, &pinth)))
	{
		if (
#ifdef _AMD64_
			IMAGE_FILE_MACHINE_AMD64
#elif defined (_X86_)
			IMAGE_FILE_MACHINE_I386
#else
#error not implemented !
#endif // DEBUG

			!= pinth->FileHeader.Machine
			)
		{
			return STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
		}

		DSC info{ 0, pinth->FileHeader.TimeDateStamp };

		if (0 <= LdrEnumerateLoadedModules(0, (PLDR_ENUM_CALLBACK)CheckModule, &info))
		{
			if (info.ImageBase)
			{
				if (ppv) *ppv = info.ImageBase;
				return STATUS_SUCCESS;
			}
		}

#ifdef _X86_
		RtlWow64EnableFsRedirection(TRUE);
#endif

		WCHAR FileName[0x180];
		UNICODE_STRING ObjectName = { 0, sizeof(FileName), FileName };

		if (0 <= (status = RtlAppendUnicodeToString(&ObjectName, USER_SHARED_DATA->NtSystemRoot)) &&
			0 <= (status = RtlAppendUnicodeToString(&ObjectName, L"\\system32\\")) &&
			0 <= (status = FindNoCfgDll(pinth->OptionalHeader.SizeOfImage, &ObjectName)))
		{
			status = LoadLibraryFromMem(ppv ? ppv : &pvImage, pvImage, pinth, &ObjectName);
		}
	}

	return status;
}