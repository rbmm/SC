#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"

void WINAPI epASM(PEB*)ASM_FUNCTION;

#pragma code_seg(".text$nm")

void* sc_end()
{
	return sc_end;
}

#pragma code_seg(".text$zz")

PVOID GetNtBase();
PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName);

HRESULT SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite)
{
	UNICODE_STRING ObjectName;

	union {
		PVOID pv;

		NTSTATUS (NTAPI * RtlDosPathNameToNtPathName_U_WithStatus) ( 
			_In_ PCWSTR  	DosName,
			_Out_ PUNICODE_STRING  	NtName,
			_Out_opt_ PWSTR *  	PartName,
			_Out_opt_ PVOID  	RelativeName 
			);

		VOID(NTAPI* RtlFreeUnicodeString)(
			_Inout_ _At_(UnicodeString->Buffer, _Frees_ptr_opt_) PUNICODE_STRING UnicodeString
			);

		NTSTATUS (NTAPI *NtCreateFile) (
			_Out_ PHANDLE FileHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_Out_ PIO_STATUS_BLOCK IoStatusBlock,
			_In_opt_ PLARGE_INTEGER AllocationSize,
			_In_ ULONG FileAttributes,
			_In_ ULONG ShareAccess,
			_In_ ULONG CreateDisposition,
			_In_ ULONG CreateOptions,
			_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
			_In_ ULONG EaLength
			);

		NTSTATUS (NTAPI * NtWriteFile) (
			_In_ HANDLE FileHandle,
			_In_opt_ HANDLE Event,
			_In_opt_ PIO_APC_ROUTINE ApcRoutine,
			_In_opt_ PVOID ApcContext,
			_Out_ PIO_STATUS_BLOCK IoStatusBlock,
			_In_reads_bytes_(Length) PVOID Buffer,
			_In_ ULONG Length,
			_In_opt_ PLARGE_INTEGER ByteOffset,
			_In_opt_ PULONG Key
			);

		NTSTATUS(NTAPI* NtClose)(
			_In_ _Post_ptr_invalid_ HANDLE Handle
			);
	};

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)GetNtBase();

	pv = GetFuncAddressEx(pidh, "RtlDosPathNameToNtPathName_U_WithStatus");
	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		LARGE_INTEGER AllocationSize = { nNumberOfBytesToWrite };

		pv = GetFuncAddressEx(pidh, "NtCreateFile");
		status = NtCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &iosb, &AllocationSize,
			0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE, 0, 0);

		pv = GetFuncAddressEx(pidh, "RtlFreeUnicodeString");
		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			pv = GetFuncAddressEx(pidh, "NtWriteFile");
			status = NtWriteFile(hFile, 0, 0, 0, &iosb, const_cast<void*>(lpBuffer), nNumberOfBytesToWrite, 0, 0);
			pv = GetFuncAddressEx(pidh, "NtClose");
			NtClose(hFile);
		}
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT PrepareCode(PCWSTR FileName, PULONG64 pb, SIZE_T n)
{
	HRESULT hr = E_OUTOFMEMORY;

	SIZE_T cch = n * (7 + 16) + 1;

	union {
		PVOID pv;

		PVOID (NTAPI * RtlAllocateHeap)(
				_In_ PVOID HeapHandle,
				_In_opt_ ULONG Flags,
				_In_ SIZE_T Size
			);

		LOGICAL (NTAPI *RtlFreeHeap)(
				_In_ PVOID HeapHandle,
				_In_opt_ ULONG Flags,
				_Frees_ptr_opt_ PVOID BaseAddress
			);

		int(__cdecl* sprintf_s)(
			_Out_writes_z_(_SizeInBytes) char* _DstBuf,
			_In_ size_t _SizeInBytes,
			_In_z_ _Printf_format_string_ const char* _Format, ...);
	};

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)GetNtBase();

	pv = GetFuncAddressEx(pidh, "RtlAllocateHeap");

	if (PSTR buf = (PSTR)RtlAllocateHeap(GetProcessHeap(), 0, cch))
	{
		hr = ERROR_INTERNAL_ERROR;

		int len;

		PSTR psz = buf;

		pv = GetFuncAddressEx(pidh, "sprintf_s");

		do 
		{
			if (0 >= (len = sprintf_s(psz, cch, "DQ 0%016I64xh\r\n", *pb++)))
			{
				break;
			}

		} while (psz += len, cch -= len, --n);

		if (!n)
		{
			hr = SaveToFile(FileName, buf, RtlPointerToOffset(buf, psz));
		}

		pv = GetFuncAddressEx(pidh, "RtlFreeHeap");
		RtlFreeHeap(GetProcessHeap(), 0, buf);
	}

	return hr;
}

// for debug epASM code only
//#pragma comment(linker, "/SECTION:.text,ERW")

void WINAPI ep2(PEB* peb)
{
	union {
		PVOID pv;
		wchar_t * (__cdecl * wcschr)(_In_z_ wchar_t *_Str, wchar_t _Ch);
		void (NTAPI* RtlExitUserProcess)(ULONG ExitCode);
		PIMAGE_NT_HEADERS (NTAPI *RtlImageNtHeader)(
				_In_ PVOID BaseOfImage
			);
	};

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)GetNtBase();

	pv = GetFuncAddressEx(pidh, "wcschr");

	PWSTR psz = wcschr(peb->ProcessParameters->CommandLine.Buffer, '*'), psz2, psz3 = 0;
	if (!psz)
	{
		epASM(peb);
	}

	if (psz2 = wcschr(++psz, '*'))
	{
		*psz2++ = 0;

		if (psz3 = wcschr(psz2, '*'))
		{
			*psz3++ = 0;
		}
	}

	ULONG cb = RtlPointerToOffset(epASM, sc_end());

	SaveToFile(psz, epASM, cb);

	if (psz2) PrepareCode(psz2, (PULONG64)epASM, (cb + 7) >> 3);

	if (psz3)
	{
		struct PE 
		{
			union {
				UCHAR pad[0x200];
				struct  
				{
					IMAGE_DOS_HEADER idh;
					IMAGE_NT_HEADERS inth;
					IMAGE_SECTION_HEADER ish;
				};
			};
			UCHAR text[];

			void* operator new(size_t s, ULONG cb)
			{
				union {
					PVOID pv;

					PVOID(NTAPI* RtlAllocateHeap)(
						_In_ PVOID HeapHandle,
						_In_opt_ ULONG Flags,
						_In_ SIZE_T Size
						);

				};

				pv = GetFuncAddressEx((PIMAGE_DOS_HEADER)GetNtBase(), "RtlAllocateHeap");
				return RtlAllocateHeap(GetProcessHeap(), 0, s + cb);
			}

			void operator delete(void* p)
			{
				union {
					PVOID pv;

					LOGICAL(NTAPI* RtlFreeHeap)(
						_In_ PVOID HeapHandle,
						_In_opt_ ULONG Flags,
						_Frees_ptr_opt_ PVOID BaseAddress
						);
				};

				pv = GetFuncAddressEx((PIMAGE_DOS_HEADER)GetNtBase(), "RtlFreeHeap");
				RtlFreeHeap(GetProcessHeap(), 0, p);
			}
		};

		if (PE* pe = new(cb) PE)
		{
			__stosb((PBYTE)pe, 0, sizeof(PE));

			pv = GetFuncAddressEx(pidh, "RtlImageNtHeader");
			PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(&__ImageBase);

			__movsb((PBYTE)&pe->idh, (PBYTE)&__ImageBase, sizeof(IMAGE_DOS_HEADER));
			__movsb((PBYTE)&pe->inth, (PBYTE)pinth, sizeof(IMAGE_NT_HEADERS));

			pe->idh.e_lfanew = sizeof(IMAGE_DOS_HEADER);
			pe->inth.FileHeader.NumberOfSections = 1;
			pe->inth.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);

			pe->inth.OptionalHeader.AddressOfEntryPoint = 0x1000;
			pe->inth.OptionalHeader.SizeOfCode = cb;
			pe->inth.OptionalHeader.BaseOfCode = 0x1000;
			pe->inth.OptionalHeader.SizeOfInitializedData = 0;
			pe->inth.OptionalHeader.SizeOfUninitializedData = 0;
			pe->inth.OptionalHeader.SectionAlignment = 0x1000;
			pe->inth.OptionalHeader.FileAlignment = 0x200;
			pe->inth.OptionalHeader.SizeOfImage = ((cb + 0x1FFF) & ~0xFFF);
			pe->inth.OptionalHeader.SizeOfHeaders = sizeof(PE);
			pe->inth.OptionalHeader.CheckSum = 0;
			pe->inth.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			__stosb((PBYTE)pe->inth.OptionalHeader.DataDirectory, 0, sizeof(IMAGE_DATA_DIRECTORY)*IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

			__movsb((PBYTE)pe->ish.Name, (PBYTE)".text\0\0", IMAGE_SIZEOF_SHORT_NAME);
			pe->ish.Misc.VirtualSize = cb;
			pe->ish.VirtualAddress = 0x1000;
			pe->ish.SizeOfRawData = cb;
			pe->ish.PointerToRawData = sizeof(PE);
			pe->ish.Characteristics = IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;

			__movsb((PBYTE)pe->text, (PBYTE)epASM, cb);

			SaveToFile(psz3, pe, sizeof(PE) + cb);

			delete pe;
		}
	}

	pv = GetFuncAddressEx(pidh, "RtlExitUserProcess");
	RtlExitUserProcess(0);
}
