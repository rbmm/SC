#include "stdafx.h"

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

NTSTATUS IsDataEndCorrect(PCSTR pcsz, ULONG s)
{
	return 0 < s && ':' == pcsz[s - 1] ? STATUS_SUCCESS : STATUS_BAD_DATA;
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

NTSTATUS MakeImport(PCWSTR pwzFileName, PSTR buf, ULONG s, PCSTR pcsz)
{
	PSTR psz = buf;

	ULONG n = 0, m = 0, i;
	ULONG_PTR v = 0;
	ULONG64 u;

	PCSTR pcszEnd = pcsz + s - 1;

	NTSTATUS status;

	while (pcsz < pcszEnd)
	{
		i = strtoul(pcsz, const_cast<char**>(&pcsz), 16);

		if (*pcsz != ':')
		{
			return STATUS_BAD_DATA;
		}

		if (!n)
		{
			n = i;
		}
		else if (n != i)
		{
			return STATUS_BAD_DATA;
		}

		i = strtoul(pcsz + 1, const_cast<char**>(&pcsz), 16);

		if (*pcsz != ' ' || m != i)
		{
			return STATUS_BAD_DATA;
		}

		m += sizeof(PVOID);
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
			PCSTR name, pszDLL;
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

			if (!v)
			{
				v = (ULONG_PTR)u;
			}
			else if (v != u)
			{
				return STATUS_BAD_DATA;
			}

			v += sizeof(PVOID);

			PCSTR pszLib = 0;

		__0:
			switch (*pcsz)
			{
			case ':':
				goto __1;
			default:
				if (!pszLib)
				{
					pszLib = pcsz;
				}
			case ' ':
				pcsz++;
				goto __0;
			}
		__1:

			if (pcsz >= pcszEnd)
			{
				return STATUS_BAD_DATA;
			}

			cchLib = RtlPointerToOffset(pszLib, pcsz);

			pszDLL = ++pcsz;

		__2:
			switch (*pcsz++)
			{
			case ':':
				return STATUS_BAD_DATA;
			default:
				goto __2;
			case '\r':
				cchDLL = RtlPointerToOffset(pszDLL, pcsz - 1);
				break;
			}

			if ('\n' != *pcsz++)
			{
				return STATUS_BAD_DATA;
			}

			if (__imp_)
			{
				__imp_ = FALSE;

#ifndef _WIN64
				// assume only __cdecl/__stdcall import. no __fastcall, begin with @
				if ('_' != *name++) return STATUS_BAD_DATA;
				--cch;
#endif // !_WIN64

				k = sprintf_s(psz, s, fmt, a, cchLib, pszLib, cch, name, k);
			}
			else
			{
				if (9 == cchDLL && !_strnicmp(pszDLL, "ntdll.dll", 9))
				{
					cchDLL = 0;
				}

				k = sprintf_s(psz, s, "\r\nHMOD %.*s, <%.*s>\r\n\r\n", cchLib, pszLib, cchDLL, pszDLL);
			}

			if (0 > k)
			{
				return STATUS_INTERNAL_ERROR;
			}

			psz += k, s -= k;

			break;
		}
	}

	return SaveToFile(pwzFileName, buf, RtlPointerToOffset(buf, psz));
}

NTSTATUS MakeImport(PCWSTR pwzFileName, PVOID ImageBase = GetModuleHandle(0))
{
	PCWSTR arr[] = { RT_RCDATA, MAKEINTRESOURCEW(1), 0 };
	PIMAGE_RESOURCE_DATA_ENTRY pirde;
	PCSTR pcsz = 0;
	ULONG s;

	NTSTATUS status;

	if (0 > (status = LdrFindResource_U(ImageBase, arr, _countof(arr), &pirde)) ||
		0 > (status = LdrAccessResource(ImageBase, pirde, (void**)&pcsz, &s)) ||
		0 > (status = IsDataEndCorrect(pcsz, s)))
	{
		return status;
	}

	if (PSTR buf = new char[s])
	{
		status = MakeImport(pwzFileName, buf, s, pcsz);

		delete[] buf;

		DbgPrint("MakeImport(%ws)=%x\r\n", pwzFileName, status);
		return status;
	}

	return STATUS_NO_MEMORY;
}

NTSTATUS CreateAsmSC(PCWSTR pwzFileName, PULONG64 pb, SIZE_T n)
{
	NTSTATUS status;

	SIZE_T cch = n * (7 + 16) + 1;

	if (PSTR buf = new char [cch])
	{
		status = STATUS_INTERNAL_ERROR;

		int len;

		PSTR psz = buf;

		do
		{
			if (0 >= (len = sprintf_s(psz, cch, "DQ 0%016I64xh\r\n", *pb++)))
			{
				break;
			}

		} while (psz += len, cch -= len, --n);

		if (!n)
		{
			status = SaveToFile(pwzFileName, buf, RtlPointerToOffset(buf, psz));
		}

		delete[] buf;

		DbgPrint("CreateAsmSC(%ws)=%x\r\n", pwzFileName, status);

		return status;
	}

	return STATUS_NO_MEMORY;
}

NTSTATUS CreateExeSC(PCWSTR pwzFileName, PVOID Base, ULONG cb)
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
		PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(&__ImageBase);

		memcpy(&pe->idh, &__ImageBase, sizeof(IMAGE_DOS_HEADER));
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

		DbgPrint("CreateAsmSC(%ws)=%x\r\n", pwzFileName, status);

		return status;
	}

	return STATUS_NO_MEMORY;
}

NTSTATUS NTAPI PrepareSC(PVOID Base, ULONG cb)
{
	PCWSTR lpCommandLine = GetCommandLineW();

	DbgPrint("PrepareSC(%p, %x, <%ws>)\r\n", Base, cb, lpCommandLine);

	PWSTR psz = wcschr(lpCommandLine, '*'), psz2, psz3 = 0;

	if (!psz)
	{
		if (psz = wcschr(lpCommandLine, '?'))
		{
			return MakeImport(psz + 1);
		}

		return DBG_CONTINUE;
	}

	// *bin*asm*exe
	if (psz2 = wcschr(++psz, '*'))
	{
		*psz2++ = 0;

		if (psz3 = wcschr(psz2, '*'))
		{
			*psz3++ = 0;
		}
	}

	NTSTATUS status = *psz ? SaveToFile(psz, Base, cb) : STATUS_SUCCESS;

	if (0 <= status)
	{
		if (psz2) status = *psz2 ? CreateAsmSC(psz2, (PULONG64)Base, (cb + 7) >> 3) : STATUS_SUCCESS;

		if (0 <= status)
		{
			if (psz3) status = *psz3 ? CreateExeSC(psz3, Base, cb) : STATUS_SUCCESS;
		}
	}

	return status;
}