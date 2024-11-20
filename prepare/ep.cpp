#include "stdafx.h"
#include "compressapi.h"

void PrintUTF8(PCSTR pcsz, ULONG len)
{
	HANDLE hFile = GetStdHandle(STD_OUTPUT_HANDLE);

	switch ((ULONG_PTR)hFile)
	{
	case 0:
	case (ULONG_PTR)INVALID_HANDLE_VALUE:
		return;
	}

	WriteFile(hFile, pcsz, len, &len, 0);
}

inline void PrintUTF8(PCSTR pcsz)
{
	PrintUTF8(pcsz, (ULONG)strlen(pcsz));
}

void PrintUTF8_v(PCSTR format, ...)
{
	va_list ap;
	va_start(ap, format);

	PSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnprintf(buf, len, format, ap)))
	{
		if (buf)
		{
			PrintUTF8(buf, len);
			break;
		}

		buf = (PSTR)alloca(++len);
	}
}

#define DbgPrint PrintUTF8_v

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName,
	_Out_ PBYTE* ppb,
	_Out_ ULONG* pcb,
	_In_opt_ ULONG cbBefore = 0,
	_In_opt_ ULONG cbAfter = 0)
{
	UNICODE_STRING ObjectName;
	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	DbgPrint("DosPathNameToNt(\"%ws\") = %x\r\n", lpFileName, status);

	if (0 <= status)
	{
		HANDLE hFile;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		IO_STATUS_BLOCK iosb;
		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

		DbgPrint("NtOpenFile(\"%wZ\") = %x\r\n", &ObjectName, status);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			FILE_STANDARD_INFORMATION fsi;
			if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
			{
				DbgPrint("FileSize=%I64u\r\n", fsi.EndOfFile.QuadPart);

				if (fsi.EndOfFile.QuadPart < 0x1000000)
				{
					if (PBYTE pb = new BYTE[cbBefore + fsi.EndOfFile.LowPart + cbAfter])
					{
						if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb + cbBefore, fsi.EndOfFile.LowPart, 0, 0)))
						{
							delete[] pb;
						}
						else
						{
							*ppb = pb;
							*pcb = (ULONG)iosb.Information;
						}

						DbgPrint("NtReadFile=%x\r\n", status);
					}
					else
					{
						status = STATUS_NO_MEMORY;
					}
				}
				else
				{
					status = STATUS_FILE_TOO_LARGE;
				}
			}

			NtClose(hFile);
		}
	}

	return status;
}

NTSTATUS SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite)
{
	UNICODE_STRING ObjectName;
	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	DbgPrint("DosPathNameToNt(\"%ws\") = %x\r\n", lpFileName, status);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		LARGE_INTEGER AllocationSize = { nNumberOfBytesToWrite };

		status = NtCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, &AllocationSize,
			0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);

		DbgPrint("CreateFile(\"%wZ\") = %x\r\n", &ObjectName, status);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			status = NtWriteFile(hFile, 0, 0, 0, &iosb, const_cast<void*>(lpBuffer), nNumberOfBytesToWrite, 0, 0);
			NtClose(hFile);

			DbgPrint("WriteFile(%x) = %x\r\n", nNumberOfBytesToWrite, status);
		}
	}

	return status;
}

NTSTATUS ProcessName(PCSTR name, PCSTR* ppcsz, PULONG plen, PINT pn)
{
	PCSTR pcsz = name;

	for (;;)
	{
		switch (*pcsz++)
		{
		case ':':
			return STATUS_BAD_DATA;

		case ' ':
			*plen = RtlPointerToOffset(name, pcsz - 1);
			*ppcsz = pcsz;
			return STATUS_SUCCESS;

		case '@':
			if (!pn)
			{
				return STATUS_BAD_DATA;
			}
			*plen = RtlPointerToOffset(name, pcsz - 1);

			ULONG n = strtoul(pcsz, const_cast<char**>(&pcsz), 10);
			if (' ' != *pcsz || (n & 3))
			{
				return STATUS_BAD_DATA;
			}
			*pn = n;
			*ppcsz = pcsz;
			return STATUS_SUCCESS;

		}
	}
}

PCSTR SkipSpace(PCSTR pcsz)
{
	while (' ' == *pcsz) ++pcsz;

	return pcsz;
}

NTSTATUS ProcessMAP(PCWSTR pszImp, PCSTR pcsz, ULONG iSection, ULONG ofs, ULONG_PTR Va, ULONG s)
{
	PSTR buf = const_cast<PSTR>(pcsz), psz = buf;

	ULONG64 u;
	BOOL f = FALSE;
	ULONG_PTR ImageBase = 0;
__0:

	PCSTR pcszLine = pcsz;

	static const char plai[] = " Preferred load address is ";

	if (!f && !memcmp(pcsz, plai, _countof(plai) - 1))
	{
		if (ImageBase)
		{
			return STATUS_BAD_DATA;
		}

		u = _strtoui64(pcsz + _countof(plai) - 1, const_cast<char**>(&pcsz), 16);

		if (!u || '\r' != *pcsz++ || '\n' != *pcsz++)
		{
			return STATUS_BAD_DATA;
		}

		ImageBase = (ULONG_PTR)u;
		Va += ImageBase;

		DbgPrint("ImageBase = %p, Va = %p\r\n", ImageBase, Va);

		goto __0;
	}

	ULONG i = strtoul(pcsz, const_cast<char**>(&pcsz), 16);

	if (':' != *pcsz)
	{
	__1:
		if (!(pcsz = strchr(pcsz, '\r')) || '\n' != *++pcsz)
		{
			return STATUS_BAD_DATA;
		}

		++pcsz;
		goto __0;
	}

	if (i != iSection)
	{
		goto __1;
	}

	i = strtoul(pcsz + 1, const_cast<char**>(&pcsz), 16);

	if (' ' != *pcsz)
	{
		return STATUS_BAD_DATA;
	}

	if (i != ofs)
	{
		goto __1;
	}

	if (f)
	{
		pcsz = pcszLine;
	}
	else
	{
		i = strtoul(pcsz + 1, const_cast<char**>(&pcsz), 16);

		if ('H' != *pcsz || s != i)
		{
			return STATUS_BAD_DATA;
		}

		f = TRUE;
		goto __1;
	}

	//////////////////////////////////////////////////////////////////////////

	NTSTATUS status;

__loop:

	i = strtoul(pcsz, const_cast<char**>(&pcsz), 16);

	if (':' != *pcsz || iSection != i)
	{
		return STATUS_BAD_DATA;
	}

	i = strtoul(pcsz + 1, const_cast<char**>(&pcsz), 16);

	if (' ' != *pcsz || ofs != i)
	{
		return STATUS_BAD_DATA;
	}

	ofs += sizeof(PVOID);
	BOOL __imp_ = FALSE;

__space:
	switch (*pcsz++)
	{
	case ' ':
		goto __space;

	default:
		return STATUS_BAD_DATA;

	case '_':
		if (memcmp(pcsz, "_imp_", 5))
		{
			return STATUS_BAD_DATA;
		}

		pcsz += 5;
		__imp_ = TRUE;

	case '\\':
		INT k = -1;
		PCSTR name;
		ULONG cch, cchDLL, cchLib;
		char a;
		PCSTR fmt;

		if (0 > (status = ProcessName(name = pcsz, &pcsz, &cch,
#ifndef _WIN64
			__imp_ ? &k :
#endif // !_WIN64
			0)))
		{
			return status;
		}

		if (0 > k)
		{
			a =
#ifndef _WIN64
				'C';
#else
				' ';
#endif // !_WIN64
			fmt = "createFunc%c %.*s, %.*s\r\n";
		}
		else
		{
			a = ' ';
			fmt = "createFunc%c %.*s, %.*s, %u\r\n";
		}

		u = _strtoui64(pcsz, const_cast<char**>(&pcsz), 16);

		if (Va != u)
		{
			return STATUS_BAD_DATA;
		}

		Va += sizeof(PVOID);

		PCSTR pszLib = 0;

	__00:
		switch (*pcsz)
		{
		case 0:
			return STATUS_BAD_DATA;
		case ':':
			goto __01;
		default:
			if (!pszLib)
			{
				pszLib = pcsz;
			}
		case ' ':
			pcsz++;
			goto __00;
		}
	__01:

		cchLib = RtlPointerToOffset(pszLib, pcsz);

		PCSTR pszDLL = ++pcsz;

	__02:
		switch (*pcsz++)
		{
		case 0:
		case ':':
			return STATUS_BAD_DATA;
		default:
			goto __02;
		case '\r':
			cchDLL = RtlPointerToOffset(pszDLL, pcsz - 1);
			break;
		}

		if ('\n' != *pcsz++)
		{
			return STATUS_BAD_DATA;
		}

		ULONG cb = RtlPointerToOffset(psz, name);

		if (__imp_)
		{
			__imp_ = FALSE;

#ifndef _WIN64
			// assume only __cdecl/__stdcall import. no __fastcall, begin with @
			if ('_' != *name++) return STATUS_BAD_DATA;
			--cch;
#endif // !_WIN64

			k = sprintf_s(psz, cb, fmt, a, cchLib, pszLib, cch, name, k);
		}
		else
		{
			if (9 == cchDLL && !_strnicmp(pszDLL, "ntdll.dll", 9))
			{
				cchDLL = 0;
			}

			k = sprintf_s(psz, cb, "\r\nHMOD %.*s, <%.*s>\r\n\r\n", cchLib, pszLib, cchDLL, pszDLL);
		}

		if (0 > k)
		{
			return STATUS_INTERNAL_ERROR;
		}

		psz += k;

		if (s -= sizeof(PVOID))
		{
			goto __loop;
		}

		status = SaveToFile(pszImp, buf, RtlPointerToOffset(buf, psz));
		return 0 > status ? status : STATUS_MORE_PROCESSING_REQUIRED;
	}
}

NTSTATUS ProcessMAP(PCWSTR pszImp, PCWSTR pszMap, ULONG iSection, ULONG ofs, ULONG_PTR Va, ULONG s)
{
	PBYTE pb;
	ULONG cb;

	DbgPrint("ProcessMAP(%04x:%08x %p [%x])...\r\n", iSection, ofs, Va, s);

	NTSTATUS status = ReadFromFile(pszMap, &pb, &cb, 0, 1);

	if (0 <= status)
	{
		pb[cb] = 0;
		status = ProcessMAP(pszImp, (PCSTR)pb, iSection, ofs, Va, s);
		delete[] pb;
	}

	return status;
}

NTSTATUS ProcessIAT(PCWSTR pszImp, PCWSTR pszMap, ULONG_PTR pvShellEnd)
{
	if (HMODULE hmod = GetModuleHandleW(0))
	{
		ULONG s;

		union {
			PVOID pv;
			PBYTE pb;
			PIMAGE_BASE_RELOCATION pibr;
		};

		if (pv = RtlImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_IAT, &s))
		{
			DbgPrint("IAT: %p [%x]\r\n", pv, s);

			if (!s || (s & (sizeof(PVOID) - 1)))
			{
				return STATUS_INTERNAL_ERROR;
			}

			if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hmod))
			{
				if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
				{
					ULONG_PTR Rva = (ULONG_PTR)pv - (ULONG_PTR)hmod;

					ULONG iSection = 0;
					PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);
					do
					{
						++iSection;

						ULONG_PTR Ofs = Rva - pish->VirtualAddress;

						if (Ofs < pish->Misc.VirtualSize)
						{
							if (Ofs + s <= pish->Misc.VirtualSize)
							{
								return ProcessMAP(pszImp, pszMap, iSection, (ULONG)Ofs, Rva, s);
							}

							break;
						}
					} while (pish++, --NumberOfSections);
				}
			}

			return STATUS_INTERNAL_ERROR;
		}

		if (pv = RtlImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &s))
		{
			pvShellEnd -= (ULONG_PTR)hmod;

			do
			{
				ULONG SizeOfBlock = pibr->SizeOfBlock;

				if (SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
				{
					return STATUS_INVALID_IMAGE_FORMAT;
				}

				ULONG VirtualAddress = pibr->VirtualAddress;

				struct TYPE_OFFSET
				{
					WORD ofs : 12;
					WORD type : 4;
				}*pu = (TYPE_OFFSET*)(pibr + 1);

				pb += SizeOfBlock, s -= SizeOfBlock, SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);

				if (SizeOfBlock & (sizeof(WORD) - 1))
				{
					return STATUS_INVALID_IMAGE_FORMAT;
				}

				SizeOfBlock >>= 1;
				do
				{
					if (pu->type)
					{
						//DbgPrint("\t## %x %08x\r\n", pu->type, VirtualAddress + pu->ofs);

						if (VirtualAddress + pu->ofs < pvShellEnd)
						{
							DbgPrint("######## !! Exist Relocs (%08x) !! ########\r\n", VirtualAddress + pu->ofs);

							return STATUS_ILLEGAL_DLL_RELOCATION;
						}
					}
				} while (pu++, --SizeOfBlock);

			} while (s);
		}

		DbgPrint("!! NO IMPORT, NO RELOCS. OK !!\r\n");

		return STATUS_SUCCESS;
	}

	return STATUS_INTERNAL_ERROR;
}

NTSTATUS I_CreateAsmSC(PCWSTR pwzFileName, const void* pcv, SIZE_T cb)
{
	NTSTATUS status;

	union {
		const void* pv;
		PULONG64 pu64;
		PULONG pu;
		PUSHORT ps;
		PUCHAR pb;
	};

	pv = pcv;

	SIZE_T n = cb >> 3;
	SIZE_T cch = n * (7 + 16) + 36;
	// DD 0ABCDEF78h.. ; 7+8
	// DW 0ABCDh..     ; 7+4
	// DB 0ABh..       ; 7+2

	if (PSTR buf = new char [cch])
	{
		status = STATUS_INTERNAL_ERROR;

		int len;
		ULONG s = 4;

		PSTR psz = buf;

		if (n)
		{
			cb -= n << 3;

			do
			{
				if (0 >= (len = sprintf_s(psz, cch, "DQ 0%016I64xh\r\n", *pu64++)))
				{
					goto __exit;
				}

			} while (psz += len, cch -= len, --n);
		}

		static const PCSTR fmt[] = { "DB 0%02xh\r\n", "DW 0%04xh\r\n", "DD 0%08xh\r\n" };
		n = _countof(fmt) - 1;

		do
		{
			if (s <= cb)
			{
				cb -= s;

				if (0 >= (len = sprintf_s(psz, cch, fmt[n], *pu & ((1ULL << (s << 3)) - 1))))
				{
					goto __exit;
				}

				psz += len, cch -= len, pb += s;
			}

		} while (s >>= 1, n--);

		status = SaveToFile(pwzFileName, buf, RtlPointerToOffset(buf, psz));

__exit:
		delete[] buf;

		DbgPrint("CreateAsmSC(%ws)=%x\r\n", pwzFileName, status);

		return status;
	}

	return STATUS_NO_MEMORY;
}

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

//## -> #
//#. -> *
//#! -> ?
//#: -> %

BOOL UnEscape(_Inout_ PWSTR str)
{
	PWSTR buf = str;
	WCHAR c;
	do
	{
		if ('#' == (c = *str++))
		{
			switch (c = *str++)
			{
			case '.':
				c = '*';
				break;
			case '!':
				c = '?';
				break;
			case ':':
				c = '%';
				break;
			case '#':
				break;
			default:
				return FALSE;
			}
		}

		*buf++ = c;

	} while (c);

	return TRUE;
}

NTSTATUS CreateAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE secret, _In_ ULONG cb)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, secret, cb, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS CreateAsmSC(PCWSTR to, PVOID pv, ULONG cb)
{
	if (PWSTR psz = wcschr(to, '?'))
	{
		*psz++ = 0;

		//while (!IsDebuggerPresent()) Sleep(100); __debugbreak();
		if (!UnEscape(const_cast<PWSTR>(to)))
		{
			return STATUS_BAD_DATA;
		}
		DbgPrint("password: \"%ws\"\r\n", to);

		BCRYPT_KEY_HANDLE hKey;
		UCHAR secret[32];
		ULONG s = sizeof(secret);
		if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, (PBYTE)to, RtlPointerToOffset(to, psz), secret, &s))
		{
			NTSTATUS status = CreateAesKey(&hKey, secret, s);

			if (0 <= status)
			{
				PBYTE pb = 0;
				s = 0;
				while (0 <= (status = BCryptEncrypt(hKey, (PBYTE)pv, cb, 0, 0, 0, pb, s, &s, BCRYPT_BLOCK_PADDING)))
				{
					if (pb)
					{
						DbgPrint("Encrypt: %x -> %x\r\n", cb, s);
						status = I_CreateAsmSC(psz, pb, s);
						break;
					}

					if (!(pb = new UCHAR[s]))
					{
						status = STATUS_NO_MEMORY;
						break;
					}
				}

				if (pb)
				{
					delete[] pb;
				}

				BCryptDestroyKey(hKey);
			}

			return status;
		}

		return GetLastError();
	}

	return I_CreateAsmSC(to, pv, cb);
}

NTSTATUS CreateZipAsmSC(PCWSTR to, PVOID pv, ULONG cb)
{
	COMPRESSOR_HANDLE CompressorHandle;
	if (CreateCompressor(COMPRESS_ALGORITHM_MSZIP, 0, &CompressorHandle))
	{
		ULONG dwError;
		SIZE_T CompressedDataSize;

		switch (dwError = BOOL_TO_ERROR(Compress(CompressorHandle, 0, cb, 0, 0, &CompressedDataSize)))
		{
		case NOERROR:
		case ERROR_INSUFFICIENT_BUFFER:
			if (PBYTE pb = new BYTE[CompressedDataSize])
			{
				if (Compress(CompressorHandle, pv, cb, pb, CompressedDataSize, &CompressedDataSize))
				{
					DbgPrint("Compress:%x >> %x [%u%%]\r\n", cb, CompressedDataSize, (CompressedDataSize * 100) / cb);
					dwError = CreateAsmSC(to, pb, (ULONG)CompressedDataSize);
				}
				else
				{
					dwError = GetLastError();
				}

				delete[] pb;
			}

			break;
		}

		CloseCompressor(CompressorHandle);

		return HRESULT_FROM_WIN32(dwError);
	}

	return GetLastError();
}

NTSTATUS CreateExeSC(PCWSTR pwzFileName, PVOID Base, ULONG cb, PVOID ImageBase)
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
			return RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, s + cb);
		}

		void operator delete(void* p)
		{
			RtlFreeHeap(GetProcessHeap(), 0, p);
		}
	};

	if (PE* pe = new(cb) PE)
	{
		PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(ImageBase);

		memcpy(&pe->idh, ImageBase, sizeof(IMAGE_DOS_HEADER));
		memcpy(&pe->inth, pinth, sizeof(IMAGE_NT_HEADERS));

		pe->idh.e_lfanew = sizeof(IMAGE_DOS_HEADER);
		pe->inth.FileHeader.NumberOfSections = 1;
		pe->inth.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
		pe->inth.FileHeader.Characteristics &= ~IMAGE_FILE_DLL;

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
		RtlZeroMemory(pe->inth.OptionalHeader.DataDirectory, sizeof(pe->inth.OptionalHeader.DataDirectory));

		memcpy(pe->ish.Name, ".text\0\0", IMAGE_SIZEOF_SHORT_NAME);
		pe->ish.Misc.VirtualSize = cb;
		pe->ish.VirtualAddress = 0x1000;
		pe->ish.SizeOfRawData = cb;
		pe->ish.PointerToRawData = sizeof(PE);
		pe->ish.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

		memcpy(pe->text, Base, cb);

		NTSTATUS status = SaveToFile(pwzFileName, pe, sizeof(PE) + cb);

		delete pe;

		DbgPrint("CreateExeSC(%ws)=%x\r\n", pwzFileName, status);

		return status;
	}

	return STATUS_NO_MEMORY;
}

NTSTATUS NTAPI PrepareSC(PVOID Base, ULONG cb, PVOID ImageBase)
{
	DbgPrint("PrepareSC(%p, %x, <%ws>)\r\n", Base, cb, GetCommandLineW());

	//*map*imp[*bin*[?[password?]]asm*exe]

	if (PWSTR psz = wcschr(GetCommandLineW(), '*'))
	{
		PWSTR pczMap = ++psz;

		if (psz = wcschr(psz, '*'))
		{
			*psz++ = 0;
			PWSTR pczImp = psz, pczBin = 0, pczAsm = 0, pczExe = 0;

			if (psz = wcschr(psz, '*'))
			{
				*psz++ = 0;
				pczBin = psz;

				if (psz = wcschr(psz, '*'))
				{
					*psz++ = 0;
					pczAsm = psz;

					if (psz = wcschr(psz, '*'))
					{
						*psz++ = 0;
						pczExe = psz;
					}
				}
			}

			NTSTATUS status = ProcessIAT(pczImp, pczMap, (ULONG_PTR)Base + cb);

			if (0 <= status)
			{
				if (pczBin && *pczBin)
				{
					status = SaveToFile(pczBin, Base, cb);
				}

				if (0 <= status)
				{
					if (pczAsm && *pczAsm)
					{
						status = '?' == *pczAsm ? CreateZipAsmSC(pczAsm + 1, Base, cb) : CreateAsmSC(pczAsm, Base, cb);
					}

					if (0 <= status)
					{
						if (pczExe && *pczExe)
						{
							status = CreateExeSC(pczExe, Base, cb, ImageBase);
						}
					}
				}
			}

			return status;
		}
	}

	return STATUS_INVALID_PARAMETER;
}