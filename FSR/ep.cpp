#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"
#include "print.h"

BOOL CALLBACK EnumThreadWndProc(HWND /*hwnd*/, LPARAM lParam)
{
	*reinterpret_cast<BOOLEAN*>(lParam) = TRUE;
	return FALSE;
}

void SusNonGui(ULONG dwProcessId, BOOL bSuspend)
{
	PCWSTR msg = bSuspend ? _YW(L"Suspend") : _YW(L"Resume");
	DbgPrint("%ws(%x, %ws)\r\n", _YW(__FUNCTIONW__), dwProcessId, msg);

	HANDLE hProcess;
	CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwProcessId };
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	BOOLEAN bGui;
	NTSTATUS status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bGui);
	if (0 > (status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid)))
	{
		DbgPrint("OpenProcess=%x\r\n", status);
	}
	else
	{
		HANDLE UniqueThread = (HANDLE)(ULONG_PTR)GetCurrentThreadId();
		HANDLE hThread, hPrevThread = 0;

		while (0 <= (status = NtGetNextThread(hProcess, hPrevThread,
			THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, 0, 0, &hThread)))
		{
			if (hPrevThread)
			{
				NtClose(hPrevThread);
			}

			hPrevThread = hThread;

			THREAD_BASIC_INFORMATION tbi;
			if (0 <= (status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), 0)))
			{
				if (UniqueThread != tbi.ClientId.UniqueThread)
				{
					bGui = FALSE;
					EnumThreadWindows((ULONG)(ULONG_PTR)tbi.ClientId.UniqueThread, _Y(EnumThreadWndProc), (LPARAM)&bGui);
					if (bGui)
					{
						DbgPrint("Skipping GUI thread %x\r\n", (ULONG)(ULONG_PTR)tbi.ClientId.UniqueThread);
					}
					else
					{
						ULONG n;
						if (0 <= (status = bSuspend ? NtSuspendThread(hThread, &n) : NtResumeThread(hThread, &n)))
						{
							DbgPrint("%ws thread %x [%x]\r\n", msg, (ULONG)(ULONG_PTR)tbi.ClientId.UniqueThread, n);
						}
					}
				}
			}

			if (0 > status)
			{
				DbgPrint("thread %x = %x\r\n", (ULONG)(ULONG_PTR)tbi.ClientId.UniqueThread, status);
			}
		}

		if (hPrevThread)
		{
			NtClose(hPrevThread);
		}

		if (STATUS_NO_MORE_ENTRIES != status)
		{
			DbgPrint("GetNextThread = %x\r\n", status);
		}

		NtClose(hProcess);
	}
}

void WINAPI ep()
{
	CPP_FUNCTION;
	{
		PrintInfo pi;
		InitPrintf();

		BOOL bInvalid = TRUE;

		if (PWSTR lpCommandLine = wcschr(GetCommandLineW(), '*'))
		{
			ULONG dwProcessId = wcstoul(lpCommandLine + 1, &lpCommandLine, 16);

			if (':' == *lpCommandLine && dwProcessId)
			{
				BOOL bSuspend = wcstoul(lpCommandLine + 1, &lpCommandLine, 16);

				if (!*lpCommandLine)
				{
					switch (bSuspend)
					{
					case 0:
					case 1:
						bInvalid = FALSE;
						SusNonGui(dwProcessId, bSuspend);
						break;
					}
				}
			}
		}

		if (bInvalid)
		{
			DbgPrint("Invalid command line. must be *pid:action\r\n\tpid: process id in hex\r\n\taction: 1|0 - suspend|resume\r\n");
		}
	}

	ExitProcess(0);
}