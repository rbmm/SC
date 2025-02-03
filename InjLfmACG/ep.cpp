#include "stdafx.h"
#include "inject.h"

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

static HRESULT Unzip(
	_In_ LPCVOID CompressedData,
	_In_ SIZE_T CompressedDataSize,
	_Out_ PVOID* pUncompressedBuffer,
	_Out_ SIZE_T* pUncompressedDataSize,
	_Out_ void** pbuf = 0,
	_In_opt_ ULONG cbBefore = 0,
	_In_opt_ ULONG cbAfter = 0)
{
	ULONG dwError;
	COMPRESSOR_HANDLE DecompressorHandle;

	if (NOERROR == (dwError = BOOL_TO_ERROR(CreateDecompressor(COMPRESS_ALGORITHM_MSZIP, 0, &DecompressorHandle))))
	{
		SIZE_T UncompressedBufferSize = 0;
		PVOID UncompressedBuffer = 0;
		PVOID buf = 0;

		while (ERROR_INSUFFICIENT_BUFFER == (dwError = BOOL_TO_ERROR(Decompress(
			DecompressorHandle, CompressedData, CompressedDataSize,
			UncompressedBuffer, UncompressedBufferSize, &UncompressedBufferSize))) && !buf)
		{
			if (!(buf = LocalAlloc(LMEM_FIXED, cbBefore + UncompressedBufferSize + cbAfter)))
			{
				dwError = ERROR_OUTOFMEMORY;
				break;
			}

			UncompressedBuffer = (PBYTE)buf + cbBefore;
		}

		if (NOERROR == dwError)
		{
			if (buf)
			{
				if (pbuf) *pbuf = buf;
				*pUncompressedDataSize = UncompressedBufferSize;
				*pUncompressedBuffer = UncompressedBuffer;
				buf = 0;
			}
			else
			{
				dwError = ERROR_INTERNAL_ERROR;
			}
		}

		if (buf)
		{
			LocalFree(buf);
		}

		CloseDecompressor(DecompressorHandle);
	}

	return HRESULT_FROM_WIN32(dwError);
}

static NTSTATUS InjectSc(
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

NTSTATUS PipeLoop(_In_ HANDLE hServer, _In_ HANDLE hProcess, _Out_ void** ppv, _Out_ PBOOL StatusFromRemote)
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
		*StatusFromRemote = TRUE;

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

extern const UCHAR ACG_begin[], ACG_end[];

NTSTATUS NTAPI InjectACG(
	_In_ HANDLE hProcess,
	_In_ IReadData* pData,
	_In_ ULONG cbData,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote)
{
	*StatusFromRemote = FALSE;

	PVOID buf, pvData;
	SIZE_T cb;
	ULONG EntryPoint = (cbData + 15) & ~15;
	NTSTATUS status;

	if (0 <= (status = Unzip(ACG_begin, ACG_end - ACG_begin, &pvData, &cb, &buf, EntryPoint)))
	{
		if (0 <= (status = pData->Read(buf, cbData)))
		{
			HANDLE hServer, hClient;
			if (0 <= (status = CreatePipePair(&hServer, &hClient)))
			{
				if (0 <= (status = NtDuplicateObject(NtCurrentProcess(), hClient,
					hProcess, &hClient, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
				{
					if (0 <= (status = InjectSc(hProcess, buf, EntryPoint + cb, EntryPoint, hClient)))
					{
						status = PipeLoop(hServer, hProcess, pImageBase, StatusFromRemote);
					}

					NtDuplicateObject(hProcess, hClient, 0, 0, 0, 0, DUPLICATE_CLOSE_SOURCE);
				}

				NtClose(hServer);
			}
		}

		LocalFree(buf);
	}

	return status;
}

NTSTATUS NTAPI InjectACG(
	_In_ HANDLE hProcess,
	_In_ const void* pvData,
	_In_ ULONG cbData,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote)
{
	struct CReadData : IReadData
	{
		const void* pvData;

		virtual NTSTATUS NTAPI Read(_In_ PVOID buf, _In_ ULONG cb)
		{
			memcpy(buf, pvData, cb);
			return STATUS_SUCCESS;
		}

		CReadData(const void* pvData) : pvData(pvData)
		{
		}

	} data(pvData);

	return InjectACG(hProcess, &data, cbData, pImageBase, StatusFromRemote);
}

NTSTATUS NTAPI RemoteUnloadDll(_In_ HANDLE hProcess, _In_ PVOID RemoteBase)
{
	return RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0,
		(PUSER_THREAD_START_ROUTINE)LdrUnloadDll, RemoteBase, 0, 0);
}