#include "stdafx.h"

#include "print.h"

#define FILE_SHARE_VALID_FLAGS          0x00000007

void ListFolder(POBJECT_ATTRIBUTES poa, PCSTR prefix)
{
	if (0 > *prefix)
	{
		// too deep
		return ;
	}

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	if (0 <= (status = NtOpenFile(&oa.RootDirectory, FILE_LIST_DIRECTORY|SYNCHRONIZE, poa, &iosb, 
		FILE_SHARE_VALID_FLAGS, 
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_DIRECTORY_FILE|FILE_OPEN_FOR_BACKUP_INTENT|FILE_OPEN_REPARSE_POINT)))
	{
		enum { cb_buf = 0x10000 };

		if (PBYTE buf = new BYTE[cb_buf])
		{
			while (0 <= (status = NtQueryDirectoryFile(oa.RootDirectory, 0, 0, 0, &iosb, 
				buf, cb_buf, FileDirectoryInformation, FALSE, 0, 0)))
			{
				PFILE_DIRECTORY_INFORMATION pfdi = (PFILE_DIRECTORY_INFORMATION)buf;
				ULONG NextEntryOffset = 0;
				do 
				{
					(ULONG_PTR&)pfdi += NextEntryOffset;

					switch (pfdi->FileNameLength)
					{
					case sizeof(WCHAR) * 2:
						if ('.' != pfdi->FileName[1]) break;
					case sizeof(WCHAR):
						if ('.' == pfdi->FileName[0]) continue;
					}

					ObjectName.Buffer = pfdi->FileName;
					ObjectName.MaximumLength = ObjectName.Length = (USHORT)pfdi->FileNameLength;

					if (pfdi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						DbgPrint("%hs%x [\"%wZ\"]\r\n", prefix, pfdi->FileAttributes, &ObjectName);

						if (!(pfdi->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
						{
							ListFolder(&oa, prefix - 1);
						}
					}
					else
					{
						DbgPrint("%hs%x %I64u \"%wZ\"\r\n", prefix, pfdi->FileAttributes, pfdi->EndOfFile.QuadPart, &ObjectName);
					}

				} while (NextEntryOffset = pfdi->NextEntryOffset);
			}

			delete [] buf;

			if (STATUS_NO_MORE_FILES == status)
			{
				status = STATUS_SUCCESS;
			}
		}

		NtClose(oa.RootDirectory);
	}

	if (status)
	{
		DbgPrint("%hs !! %x \"%wZ\"\r\n", prefix, status, poa->ObjectName);
	}
}

NTSTATUS ListFolder(PCWSTR pszName, ULONG Level)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(pszName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		PSTR prefix = (PSTR)alloca(Level + 2);
		prefix[0] = -1;
		memset(prefix + 1, '\t', Level);
		prefix[Level + 1] = 0;
		ListFolder(&oa, prefix + Level + 1);
		RtlFreeUnicodeString(&ObjectName);
	}

	return status;
}