#include "stdafx.h"

#include "print.h"

#define TSN(r) case r: return #r

PCSTR GetThreadWaitReason(KWAIT_REASON wr, PSTR buf, ULONG cch)
{
	switch (wr)
	{
		TSN(Executive);
		TSN(FreePage);
		TSN(PageIn);
		TSN(PoolAllocation);
		TSN(DelayExecution);
		TSN(Suspended);
		TSN(UserRequest);
		TSN(WrExecutive);
		TSN(WrFreePage);
		TSN(WrPageIn);
		TSN(WrPoolAllocation);
		TSN(WrDelayExecution);
		TSN(WrSuspended);
		TSN(WrUserRequest);
		TSN(WrEventPair); //WrSpare0
		TSN(WrQueue);
		TSN(WrLpcReceive);
		TSN(WrLpcReply);
		TSN(WrVirtualMemory);
		TSN(WrPageOut);
		TSN(WrRendezvous);
		TSN(WrKeyedEvent);
		TSN(WrTerminated);
		TSN(WrProcessInSwap);
		TSN(WrCpuRateControl);
		TSN(WrCalloutStack);
		TSN(WrKernel);
		TSN(WrResource);
		TSN(WrPushLock);
		TSN(WrMutex);
		TSN(WrQuantumEnd);
		TSN(WrDispatchInt);
		TSN(WrPreempted);
		TSN(WrYieldExecution);
		TSN(WrFastMutex);
		TSN(WrGuardedMutex);
		TSN(WrRundown);
		TSN(WrAlertByThreadId);
		TSN(WrDeferredPreempt);
		TSN(WrPhysicalFault);
		TSN(WrIoRing);
		TSN(WrMdlCache);
	}

	sprintf_s(buf, cch, "[%x]", wr);

	return buf;
}

PCSTR GetThreadStateName(KTHREAD_STATE st, PSTR buf, ULONG cch)
{
	switch (st)
	{
		TSN(Initialized);
		TSN(Ready);
		TSN(Running);
		TSN(Standby);
		TSN(Terminated);
		TSN(Waiting);
		TSN(Transition);
		TSN(DeferredReady);
		TSN(GateWaitObsolete);
		TSN(WaitingForProcessInSwap);
	}

	sprintf_s(buf, cch, "[%x]", st);

	return buf;
}

/*
 *	List all running processes (name + pid)
 */

NTSTATUS List_all_running_processes()
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PVOID buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				union {
					PVOID pv;
					PBYTE pb;
					PSYSTEM_PROCESS_INFORMATION pspi;
				};

				pv = buf;
				ULONG NextEntryOffset = 0, i = 0;

				do 
				{
					pb += NextEntryOffset;

					DbgPrint("%x: %x(%x) [%x] %x \"%wZ\"\r\n", i++, 
						pspi->UniqueProcessId, 
						pspi->InheritedFromUniqueProcessId,
						pspi->SessionId,
						pspi->NumberOfThreads,
						pspi->ImageName);

				} while (NextEntryOffset = pspi->NextEntryOffset);

			}

			delete [] (buf);
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

NTSTATUS DumpProcessThreads(ULONG_PTR dwProcessId)
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PVOID buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemExtendedProcessInformation, buf, cb, &cb)))
			{
				status = STATUS_NOT_FOUND;

				union {
					PVOID pv;
					PBYTE pb;
					PSYSTEM_PROCESS_INFORMATION pspi;
				};

				pv = buf;
				ULONG NextEntryOffset = 0;

				do 
				{
					pb += NextEntryOffset;

					if ((HANDLE)dwProcessId == pspi->UniqueProcessId)
					{
						ULONG NumberOfThreads = pspi->NumberOfThreads;
						DbgPrint("PID=%u NumberOfThreads=%u\r\n", dwProcessId, NumberOfThreads);

						status = STATUS_SUCCESS;

						if (NumberOfThreads)
						{
							PSYSTEM_EXTENDED_THREAD_INFORMATION TH = pspi->Threads;
							do 
							{
								char sz[16];

								DbgPrint("%x: %p %p %hs\r\n", 
									TH->ClientId.UniqueThread,
									TH->TebBase,
									TH->Win32StartAddress,
									Waiting == TH->ThreadState
									? GetThreadWaitReason(TH->WaitReason, sz, _countof(sz)) 
									: GetThreadStateName(TH->ThreadState, sz, _countof(sz))
									);
								
							} while (TH++, --NumberOfThreads);
						}

						break;
					}

				} while (NextEntryOffset = pspi->NextEntryOffset);

			}

			delete [] (buf);
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	DbgPrint("DumpProcessThreads(%u)=%x\r\n", dwProcessId, status);

	if (status)
	{
		PrintError(HRESULT_FROM_NT(status));
	}

	return status;
}