#include "stdafx.h"

_NT_BEGIN

NTSTATUS CreatePlaceHolder(PCWSTR lpFileName, ULONG SizeOfImage)
{
	struct SEF : IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER
	{
	} y {};

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	SizeOfImage = (SizeOfImage + si.dwAllocationGranularity - 1) & ~(si.dwAllocationGranularity - 1);

	SIZE_T Alignment = si.dwPageSize - 1;

	y.e_magic = IMAGE_DOS_SIGNATURE;
	y.e_lfanew = sizeof(IMAGE_DOS_HEADER);
	y.Signature = IMAGE_NT_SIGNATURE;

#ifdef _WIN64
	y.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	y.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	y.OptionalHeader.ImageBase = 1 + (ULONG_PTR)MAXULONG;
#else
	y.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	y.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	y.OptionalHeader.ImageBase = 0x40000000;
#endif
	y.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	y.FileHeader.NumberOfSections = 1;
	y.FileHeader.Characteristics = IMAGE_FILE_DLL|IMAGE_FILE_EXECUTABLE_IMAGE|IMAGE_FILE_LARGE_ADDRESS_AWARE;
	y.OptionalHeader.SectionAlignment = si.dwPageSize;
	y.OptionalHeader.FileAlignment = si.dwPageSize;
	y.OptionalHeader.MajorOperatingSystemVersion = _WIN32_WINNT_VISTA >> 8;
	y.OptionalHeader.MajorSubsystemVersion = _WIN32_WINNT_VISTA >> 8;
	y.OptionalHeader.SizeOfHeaders = (ULONG)((sizeof(y) + Alignment) & ~Alignment);
	y.OptionalHeader.SizeOfImage = SizeOfImage;
	y.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	y.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE|IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA|IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	y.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	y.VirtualAddress = si.dwPageSize;
	y.Misc.VirtualSize = SizeOfImage - si.dwPageSize;
	y.Characteristics = IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;

	NTSTATUS status;
	UNICODE_STRING ObjectName;
	if (0 <= (status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0)))
	{
		HANDLE hFile = 0;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		
		FILE_BASIC_INFORMATION fbi;
		if (0 > ZwQueryAttributesFile(&oa, &fbi))
		{
			status = NtCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &iosb, 0, 
				FILE_ATTRIBUTE_TEMPORARY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, 0,
				FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE, 0, 0);
		}
		
		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status && hFile)
		{
			status = NtWriteFile(hFile, 0, 0, 0, &iosb, &y, sizeof(y), 0, 0);
			NtClose(hFile);
		}
	}
	
	return status;
}

struct IMAGE_Ctx : public TEB_ACTIVE_FRAME
{
	inline static const char FrameName[] = "{0A0659E5-2962-480a-9A6F-01A02C5C043B}";

	PIMAGE_NT_HEADERS _M_pinth;
	PVOID _M_retAddr = 0, _M_pvImage, *_M_pBaseAddress = 0, _M_hmod = 0;
	PCWSTR _M_lpFileName;
	NTSTATUS _M_status = STATUS_UNSUCCESSFUL;

	IMAGE_Ctx(PVOID pvImage, PIMAGE_NT_HEADERS pinth, PCWSTR lpFileName) 
		: _M_pvImage(pvImage), _M_pinth(pinth), _M_lpFileName(lpFileName)
	{
		const static TEB_ACTIVE_FRAME_CONTEXT FrameContext = { 0, FrameName };
		Context = &FrameContext;
		Flags = 0;
		RtlPushFrame(this);
	}

	~IMAGE_Ctx()
	{
		RtlPopFrame(this);
	}

	static IMAGE_Ctx* get()
	{
		if (TEB_ACTIVE_FRAME * frame = RtlGetFrame())
		{
			do 
			{
				if (frame->Context->FrameName == FrameName)
				{
					return static_cast<IMAGE_Ctx*>(frame);
				}
			} while (frame = frame->Previous);
		}

		return 0;
	}
};

NTSTATUS OverwriteSection(_In_ PVOID BaseAddress, _In_ PVOID pvImage, _In_ PIMAGE_NT_HEADERS pinth)
{
	ULONG op, cb = pinth->OptionalHeader.SizeOfHeaders, VirtualSize, SizeOfRawData;
	PVOID pv = BaseAddress, VirtualAddress;
	SIZE_T ProtectSize = cb;

	NTSTATUS status;
	if (0 > (status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &ProtectSize, PAGE_READWRITE, &op)))
	{
		return status;
	}

	memcpy(BaseAddress, pvImage, cb);

	ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &ProtectSize, PAGE_READONLY, &op);

	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do 
		{
			if (VirtualSize = pish->Misc.VirtualSize)
			{
				VirtualAddress = RtlOffsetToPointer(BaseAddress, pish->VirtualAddress);

				ULONG Characteristics = pish->Characteristics;

				if (0 > (status = ZwProtectVirtualMemory(NtCurrentProcess(), &(pv = VirtualAddress), 
					&(ProtectSize = VirtualSize), 
					Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &op)))
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
					if (0 > (status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &ProtectSize, 
						Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READONLY, &op)))
					{
						return status;
					}
				}
			}

		} while (pish++, --NumberOfSections);
	}

	return STATUS_SUCCESS;
}

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"

NTSTATUS __fastcall retFromMapViewOfSection(NTSTATUS status)
{
	CPP_FUNCTION;

	if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
	{
		*(void**)_AddressOfReturnAddress() = ctx->_M_retAddr;

		if (0 <= status)
		{
			PVOID BaseAddress = *ctx->_M_pBaseAddress;

			if (0 <= (status = OverwriteSection(BaseAddress, ctx->_M_pvImage, ctx->_M_pinth)))
			{
				if (BaseAddress != (PVOID)ctx->_M_pinth->OptionalHeader.ImageBase)
				{
					status = STATUS_IMAGE_NOT_AT_BASE;
				}
			}

			if (0 > status)
			{
				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

				*ctx->_M_pBaseAddress = 0;
			}
			else
			{
				ctx->_M_hmod = BaseAddress;
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
	
	if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP && ExceptionRecord->ExceptionAddress == ZwMapViewOfSection)
	{
		if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
		{
			PCWSTR lpFileName = (PCWSTR)reinterpret_cast<PNT_TIB>(NtCurrentTeb())->ArbitraryUserPointer;
			if (lpFileName && !wcscmp(lpFileName, ctx->_M_lpFileName))
			{
				ctx->_M_pBaseAddress =
#ifdef _WIN64
					(void**)ContextRecord->R8;

#define SP Rsp
#else
#define SP Esp
					((void***)ContextRecord->Esp)[3];
#endif

				*(PSIZE_T)((void**)ContextRecord->SP)[7] = ctx->_M_pinth->OptionalHeader.SizeOfImage;

				ctx->_M_retAddr = ((void**)ContextRecord->SP)[0];

				((void**)ContextRecord->SP)[0] = aretFromMapViewOfSection;
			}
		}

		ContextRecord->EFlags |= 0x10000;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS LoadLibraryFromMem(_Out_ HMODULE* phmod, _In_ PVOID pvImage, _In_ PIMAGE_NT_HEADERS pinth, _In_ PCWSTR lpFileName)
{
	if (PVOID VectoredHandlerHandle = RtlAddVectoredExceptionHandler(TRUE, MyVexHandler))
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ctx.Dr3 = (ULONG_PTR)ZwMapViewOfSection;
		ctx.Dr7 = 0x440;

		NTSTATUS status;
		if (0 <= (status = ZwSetContextThread(NtCurrentThread(), &ctx)))
		{
			IMAGE_Ctx ictx(pvImage, pinth, lpFileName);

			UNICODE_STRING us;
			RtlInitUnicodeString(&us, lpFileName);

			status = LdrLoadDll(0, 0, &us, phmod);

			ctx.Dr3 = 0;
			ctx.Dr7 = 0x400;
			ZwSetContextThread(NtCurrentThread(), &ctx);

			if (0 <= status && 0 > ictx._M_status)
			{
				LdrUnloadDll(*phmod);
			}

			status = ictx._M_status;
		}

		RtlRemoveVectoredExceptionHandler(VectoredHandlerHandle);

		return status;
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS LoadLibraryFromMem(_Out_ HMODULE* phmod, _In_ PVOID pvImage)
{
	PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(pvImage);

	if (!pinth)
	{
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	WCHAR buf[32];
	if (0 < swprintf_s(buf, _countof(buf), L"%%tmp%%\\$$%X.%X.tmp", 
		pinth->OptionalHeader.SizeOfImage, pinth->FileHeader.Machine))
	{
		ULONG cch = 0;
		PWSTR lpFileName = 0;
		while (cch = ExpandEnvironmentStringsW(buf, lpFileName, cch))
		{
			if (lpFileName)
			{
				NTSTATUS status = CreatePlaceHolder(lpFileName, pinth->OptionalHeader.SizeOfImage);
				if (0 <= status)
				{
					status = LoadLibraryFromMem(phmod, pvImage, pinth, lpFileName);
				}
				return status;
			}

			lpFileName = (PWSTR)alloca(cch * sizeof(WCHAR));
		}

		return HRESULT_FROM_WIN32(GetLastError());
	}

	return STATUS_INTERNAL_ERROR;
}

_NT_END