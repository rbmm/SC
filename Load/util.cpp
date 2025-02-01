#include "stdafx.h"
#include "zip.h"
#include "msgbox.h"

extern const UCHAR ACG_begin[], ACG_end[];

NTSTATUS ReadFromFileWithUnzip(
	_In_ PCWSTR lpFileName,
	_Out_ void** ppv,
	_Out_ SIZE_T* pcb,
	_Out_ ULONG* pcbFile,
	_In_ LPCVOID CompressedData = 0,
	_In_ SIZE_T CompressedDataSize = 0)
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
				if (fsi.EndOfFile.QuadPart < 0x1000000)
				{
					PVOID pv, pvData;
					SIZE_T cb;
					ULONG cbFile = (fsi.EndOfFile.LowPart + 15) & ~15;

					if (0 <= (status = Unzip(CompressedData, CompressedDataSize, &pvData, &cb, &pv, cbFile)))
					{
						if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pv, fsi.EndOfFile.LowPart, 0, 0)))
						{
							LocalFree(pv);
						}
						else
						{
							*ppv = pv;
							*pcb = cbFile + cb;
							*pcbFile = cbFile;
						}
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

NTSTATUS InjectSc(
	_In_ HANDLE hProcess,
	_In_ PVOID pv,
	_In_ SIZE_T cb,
	_In_ ULONG EntryPoint,
	_In_ PVOID Param)
{
	NTSTATUS status;

	SIZE_T RegionSize = cb;
	PVOID BaseAddress = 0;

	if (0 <= (status = NtAllocateVirtualMemory(hProcess, &BaseAddress, 0, &RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		if (0 <= (status = ZwWriteVirtualMemory(hProcess, BaseAddress, pv, cb, &cb)))
		{
			HANDLE hThread;
			if (0 <= (status = RtlCreateUserThread(hProcess, 0, TRUE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)RtlExitUserThread, 0, &hThread, 0)))
			{
				if (0 <= (status = ZwQueueApcThread(hThread,
					(PPS_APC_ROUTINE)RtlOffsetToPointer(BaseAddress, EntryPoint),
					BaseAddress, (PVOID)(ULONG_PTR)EntryPoint, Param)))
				{
					ZwQueueApcThread(hThread, (PPS_APC_ROUTINE)VirtualFree, BaseAddress, 0, (PVOID)(ULONG_PTR)MEM_RELEASE);
					BaseAddress = 0;
				}

				ZwResumeThread(hThread, 0);
				NtClose(hThread);
			}
		}

		if (BaseAddress) NtFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, MEM_RELEASE);
	}

	return status;
}

NTSTATUS SearchAndReadFile(
	_In_ PCWSTR FileName, 
	_Out_ void** BaseAddress, 
	_Out_ PSIZE_T ViewSize,
	_Out_ ULONG* pcbFile = 0,
	_In_ LPCVOID CompressedData = 0,
	_In_ SIZE_T CompressedDataSize = 0)
{
	WCHAR buf[MAX_PATH] = L"\\??\\";
	if (SearchPathW(0, FileName, L".dll", _countof(buf) - 4, buf + 4, 0))
	{
		ULONG cb;
		return ReadFromFileWithUnzip(buf, BaseAddress, ViewSize, pcbFile ? pcbFile : &cb, CompressedData, CompressedDataSize);
	}

	return GetLastErrorEx();
}

NTSTATUS PipeLoop(_In_ HANDLE hServer, _In_ HANDLE hProcess, _Out_ void** ppv)
{
	struct IN_REQ
	{
		enum { tProtect = 'prct', tStatus } op;
		union {
			DWORD flNewProtect;
			NTSTATUS status;
		};
		PVOID lpAddress;
		SIZE_T dwSize;
	} req;

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	while (0 <= (status = NtReadFile(hServer, 0, 0, 0, &iosb, &req, sizeof(req), 0, 0)))
	{
		if (sizeof(IN_REQ) == iosb.Information)
		{
			ULONG op;
			switch (req.op)
			{
			case IN_REQ::tProtect:
				status = ZwProtectVirtualMemory(hProcess, &req.lpAddress, &req.dwSize, req.flNewProtect, &op);
				if (0 > (status = NtWriteFile(hServer, 0, 0, 0, &iosb, &status, sizeof(status), 0, 0)))
				{
					return status;
				}
				break;

			case IN_REQ::tStatus:
				*ppv = req.lpAddress;
				return req.status;

			default:
				return STATUS_BAD_DATA;
			}
		}
		else
		{
			return STATUS_INFO_LENGTH_MISMATCH;
		}
	}

	return status;
}

#define FILE_SHARE_VALID_FLAGS 7

NTSTATUS CreatePipePair(PHANDLE phServerPipe, PHANDLE phClientPipe)
{
	HANDLE hFile;

	IO_STATUS_BLOCK iosb;

	UNICODE_STRING NamedPipe;
	RtlInitUnicodeString(&NamedPipe, L"\\Device\\NamedPipe\\");

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &NamedPipe, OBJ_CASE_INSENSITIVE };

	NTSTATUS status;

	if (0 <= (status = NtOpenFile(&hFile, SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, 0)))
	{
		oa.RootDirectory = hFile;

		LARGE_INTEGER timeout = { 0, (LONG)MINLONG };
		UNICODE_STRING empty = {};

		oa.ObjectName = &empty;

		if (0 <= (status = NtCreateNamedPipeFile(phServerPipe,
			FILE_READ_ATTRIBUTES | FILE_READ_DATA |
			FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA |
			FILE_CREATE_PIPE_INSTANCE | SYNCHRONIZE,
			&oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_CREATE,
			FILE_SYNCHRONOUS_IO_NONALERT,
			FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE,
			FILE_PIPE_QUEUE_OPERATION, 1, 0, 0, &timeout)))
		{
			oa.RootDirectory = *phServerPipe;

			if (0 > (status = NtOpenFile(phClientPipe, SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_DATA |
				FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA, &oa, &iosb, FILE_SHARE_VALID_FLAGS,
				FILE_SYNCHRONOUS_IO_NONALERT)))
			{
				NtClose(oa.RootDirectory);
				*phServerPipe = 0;
			}
		}

		NtClose(hFile);
	}

	return status;
}

NTSTATUS InjectScACG(
	_In_ HANDLE hProcess,
	_In_ PCWSTR lpFileName,
	_Out_ PVOID* pImageBase)
{
	PVOID pv;
	SIZE_T cb;
	ULONG EntryPoint;
	NTSTATUS status = SearchAndReadFile(lpFileName, &pv, &cb, &EntryPoint, ACG_begin, ACG_end - ACG_begin);

	if (0 <= status)
	{
		HANDLE hServer, hClient;
		if (0 <= (status = CreatePipePair(&hServer, &hClient)))
		{
			if (0 <= (status = NtDuplicateObject(NtCurrentProcess(), hClient,
				hProcess, &hClient, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
			{
				if (0 <= (status = InjectSc(hProcess, pv, cb, EntryPoint, hClient)))
				{
					status = PipeLoop(hServer, hProcess, pImageBase);
				}

				NtDuplicateObject(hProcess, hClient, 0, 0, 0, 0, DUPLICATE_CLOSE_SOURCE);
			}

			NtClose(hServer);
		}

		LocalFree(pv);
	}

	return status;
}

NTSTATUS RemoteUnloadDll(_In_ HANDLE hProcess, _In_ PVOID RemoteBase)
{
	return RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0,
		(PUSER_THREAD_START_ROUTINE)LdrUnloadDll, RemoteBase, 0, 0);
}