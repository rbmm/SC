#include "stdafx.h"

#include "wow.h"

ULONG GetNameOrdinal(PVOID BaseAddress, PULONG AddressOfNames, ULONG NumberOfNames, PCSTR Name)
{
	if (NumberOfNames)
	{
		DWORD a = 0, o;

		do 
		{
			o = (a + NumberOfNames) >> 1;

			int i = strcmp(RtlOffsetToPointer(BaseAddress, AddressOfNames[o]), Name);

			if (!i)
			{
				return o;
			}

			0 > i ? a = o + 1 : NumberOfNames = o;

		} while (a < NumberOfNames);
	}

	return MAXDWORD;
}

ULONG GetFunc(ULONG NumberOfFunctions, 
			  PIMAGE_EXPORT_DIRECTORY pied, 
			  ULONG size, 
			  PVOID BaseAddress, 
			  PCSTR lpProcName, 
			  ULONG Ordinal)
{
	ULONG exportRVA = RtlPointerToOffset(BaseAddress, pied), rva;

	if (Ordinal)
	{
		Ordinal -= pied->Base;
	}
	else
	{
		if (0 > (int)(Ordinal = GetNameOrdinal(BaseAddress, 
			(PULONG)RtlOffsetToPointer(BaseAddress, pied->AddressOfNames), pied->NumberOfNames, lpProcName)))
		{
			return 0;
		}

		Ordinal = ((PUSHORT)RtlOffsetToPointer(BaseAddress, pied->AddressOfNameOrdinals))[Ordinal];
	}

	if (Ordinal < NumberOfFunctions)
	{
		rva = ((PULONG)RtlOffsetToPointer(BaseAddress, pied->AddressOfFunctions))[Ordinal];

		if ((ULONG_PTR)rva - (ULONG_PTR)exportRVA >= size)
		{
			return rva;
		}
	}

	return 0;
}

NTSTATUS GetTransferAddress(HANDLE hSection, void** TransferAddress)
{
	SECTION_IMAGE_INFORMATION sii;
	NTSTATUS status = ZwQuerySection(hSection, SectionImageInformation, &sii, sizeof(sii), 0);

	if (0 <= status)
	{
		if (sii.TransferAddress)
		{
			*TransferAddress = sii.TransferAddress;

			return STATUS_SUCCESS;
		}

		return STATUS_SECTION_NOT_IMAGE; 
	}

	return status;
}

NTSTATUS GetWowInfo(FUNC* pfn, ULONG n)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, L"\\KnownDlls32\\ntdll.dll");
	
	HANDLE hSection;
	NTSTATUS status = ZwOpenSection(&hSection, SECTION_MAP_EXECUTE|SECTION_QUERY, &oa);

	if (0 <= status)
	{
		PVOID TransferAddress = 0;
		PVOID BaseAddress = 0;
		SIZE_T ViewSize = 0;

		0 <= (status = GetTransferAddress(hSection, &TransferAddress)) && 
			0 <= (status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &ViewSize,
			ViewUnmap, 0, PAGE_EXECUTE));

		NtClose(hSection);

		if (0 <= status)
		{
			status = n;

			if (PIMAGE_NT_HEADERS32 pinth = (PIMAGE_NT_HEADERS32)RtlImageNtHeader(BaseAddress))
			{
				ULONG size;

				if (PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)
					RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size))
				{
					if (ULONG NumberOfFunctions = pied->NumberOfFunctions)
					{
						do 
						{
							PCSTR name = pfn->name;

							ULONG ordinal = 0;

							if (IS_INTRESOURCE(name))
							{
								ordinal = (ULONG)(ULONG_PTR)name;
								name = 0;
							}

							pfn->pfn = 0;

							if (ULONG rva = GetFunc(NumberOfFunctions, pied, size, BaseAddress, name, ordinal))
							{
								pfn->pfn = (PBYTE)TransferAddress - pinth->OptionalHeader.AddressOfEntryPoint + rva;
								status--;
							}

						} while (pfn++, --n);
					}
				}
			}

			ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
		}
	}

	return status;
}

