#include "stdafx.h"
#include "../InjLfmACG/inject.h"

struct CFileData : IReadData
{
	HANDLE _M_hFile = 0;

	~CFileData()
	{
		if (_M_hFile) NtClose(_M_hFile);
	}

	virtual NTSTATUS NTAPI Read(_In_ PVOID buf, _In_ ULONG cb)
	{
		if (_M_hFile)
		{
			IO_STATUS_BLOCK iosb;
			NTSTATUS status = NtReadFile(_M_hFile, 0, 0, 0, &iosb, buf, cb, 0, 0);
			NtClose(_M_hFile);
			_M_hFile = 0;

			return status;
		}

		return STATUS_INVALID_HANDLE;
	}

	NTSTATUS Open(_In_ PCWSTR lpFileName, _Out_ PULONG pcbFile)
	{
		UNICODE_STRING ObjectName;
		NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

		if (0 <= status)
		{
			HANDLE hFile;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
			IO_STATUS_BLOCK iosb;
			status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

			RtlFreeUnicodeString(&ObjectName);

			if (0 <= status)
			{
				FILE_STANDARD_INFORMATION fsi;
				if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
				{
					_M_hFile = hFile;
					*pcbFile = fsi.EndOfFile.LowPart;

					return STATUS_SUCCESS;
				}

				NtClose(hFile);
			}
		}

		return status;
	}

	NTSTATUS SearchAndOpen(_In_ PCWSTR lpFileName, _Out_ PULONG pcbFile)
	{
		WCHAR buf[MAX_PATH];
		if (SearchPathW(0, lpFileName, L".dll", _countof(buf), buf, 0))
		{
			return Open(buf, pcbFile);
		}

		return STATUS_OBJECT_NAME_NOT_FOUND;
	}
};
NTSTATUS NTAPI InjectDLL(_In_ HANDLE hProcess, _In_ const void* pvData, _In_ ULONG cbData);
NTSTATUS InjectScACG(
	_In_ HANDLE hProcess,
	_In_ PCWSTR lpFileName,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote)
{
	CFileData file;

	ULONG cbFile;
	NTSTATUS status = file.SearchAndOpen(lpFileName, &cbFile);

	if (0 <= status)
	{
		if (cbFile < 0x1000000)
		{
			if (0x200 < cbFile)
			{
				return InjectACG(hProcess, &file, cbFile, pImageBase, StatusFromRemote);
			}

			return STATUS_INVALID_IMAGE_FORMAT;
		}

		return STATUS_FILE_TOO_LARGE;
	}

	return status;
}

NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ ULONG_PTR Size, _Out_opt_ void** ppv);

NTSTATUS InjectToSelf(_In_ PCWSTR lpFileName, _Out_ PVOID* pImageBase)
{
	CFileData file;

	ULONG cbFile;
	NTSTATUS status = file.SearchAndOpen(lpFileName, &cbFile);

	if (0 <= status)
	{
		status = STATUS_FILE_TOO_LARGE;

		if (cbFile < 0x1000000)
		{
			status = STATUS_INVALID_IMAGE_FORMAT;

			if (0x200 < cbFile)
			{
				status = STATUS_NO_MEMORY;

				if (PVOID buf = new UCHAR[cbFile])
				{
					if (0 <= (status = file.Read(buf, cbFile)))
					{
						status = LoadLibraryFromMem(buf, cbFile, pImageBase);
					}

					delete[] buf;
				}
			}
		}
	}

	return status;
}