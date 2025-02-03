#include "stdafx.h"
#include "inject.h"

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

extern const UCHAR SC_begin[], SC_end[];

NTSTATUS NTAPI InjectDLL(_In_ HANDLE hProcess, _In_ const void* pvData,_In_ ULONG cbData)
{
	SIZE_T cb = SC_end - SC_begin;
	ULONG EntryPoint = (cbData + 15) & ~15;

	if (PVOID buf = LocalAlloc(LMEM_FIXED, EntryPoint + cb))
	{
		memcpy((PBYTE)memcpy(buf, pvData, cbData) + EntryPoint, SC_begin, cb);

		NTSTATUS status = InjectSc(hProcess, buf, EntryPoint + cb, EntryPoint, 0);
		LocalFree(buf);
		return status;
	}

	return STATUS_NO_MEMORY;
}