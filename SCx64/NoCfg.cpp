#include "stdafx.h"

BOOLEAN IsImageOk(_In_ ULONG SizeOfImage, _In_ HANDLE hSection, _In_ ULONG Machine, _In_ ULONG Magic)
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
					PIMAGE_LOAD_CONFIG_DIRECTORY32 picd32;
					PIMAGE_LOAD_CONFIG_DIRECTORY64 picd64;
				};

				pv = RtlOffsetToPointer(BaseAddress, VirtualAddress);

				PIMAGE_SECTION_HEADER pish = 0;
				DWORD NumberOfSections = 0;

				if (pinth->FileHeader.Machine == Machine &&
					pinth->OptionalHeader.Magic == Magic &&
					pinth->OptionalHeader.SizeOfImage >= SizeOfImage)
				{
					if (NumberOfSections = pinth->FileHeader.NumberOfSections)
					{
						pish = IMAGE_FIRST_SECTION(pinth);
					}
					ULONG s;

					if (pv = RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &s))
					{
						switch (Magic)
						{
						case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
							fOk = picd32->Size < __builtin_offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags) ||
								!picd32->GuardCFFunctionCount;
							break;

						case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
							fOk = picd64->Size < __builtin_offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags) ||
								!picd64->GuardCFFunctionCount;
							break;
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
		}

		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	}

	return fOk;
}

PCWSTR System32()
{
	return L"\\systemroot\\system32";
}

PCWSTR Syswow64()
{
	return L"\\systemroot\\syswow64";
}

PCWSTR DLLMask()
{
	return L"*.dll";
}

NTSTATUS FindNoCfgDll(_In_ ULONG Machine, _In_ ULONG Magic, _In_ ULONG SizeOfImage, _Out_ PHANDLE SectionHandle)
{
	PCWSTR path;
	NTSTATUS status;

#ifdef _X86_
	PVOID wow;
	if (0 > (status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &wow, sizeof(wow), 0)))
	{
		return status;
	}

	if (!wow)
	{
		path = System32();
	}
	else
#endif
	{
		switch (Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			path = Syswow64();
			break;

		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			path = System32();
			break;

		default: return STATUS_NOT_SUPPORTED;
		}
	}

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, path);

	if (0 <= (status = NtOpenFile(&oa.RootDirectory,
		FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		status = STATUS_NO_MEMORY;

		enum { buf_size = 0x10000 };

		if (PVOID buf = new UCHAR[buf_size])
		{
			UNICODE_STRING DLL;
			RtlInitUnicodeString(&DLL, DLLMask());

			while (0 <= (status = NtQueryDirectoryFile(oa.RootDirectory,
				0, 0, 0, &iosb, buf, buf_size, FileDirectoryInformation,
				FALSE, &DLL, FALSE)))
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

						if (0 <= NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT))
						{
							BOOLEAN fOk = FALSE;

							HANDLE hSection;

							if (0 <= NtCreateSection(&hSection, SECTION_MAP_READ, 0, 0, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile))
							{
								fOk = IsImageOk(SizeOfImage, hSection, Machine, Magic);

								NtClose(hSection);

								if (fOk)
								{
									fOk = 0 <= NtCreateSection(SectionHandle,
										SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE,
										0, 0, PAGE_WRITECOPY, SEC_IMAGE, hFile);
								}
							}

							NtClose(hFile);

							if (0 <= status)
							{
								if (fOk)
								{
									goto __exit;
								}
							}
						}
					}

				} while (NextEntryOffset = pfdi->NextEntryOffset);
			}
__exit:
			delete [] buf;
		}
		NtClose(oa.RootDirectory);
	}

	return status;
}
