#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

BOOL Download(_In_ PCWSTR lpszServerName, _In_ PCWSTR lpszObjectName, _Out_ void** ppv, _Out_ ULONG* pcb)
{
	BOOL fOk = FALSE;

	if (HINTERNET hSession = WinHttpOpen(0, 0, 0, 0, 0))
	{
		if (HINTERNET hConnect = WinHttpConnect(hSession, lpszServerName, INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET hRequest = WinHttpOpenRequest(hConnect, 0,
				lpszObjectName, 0, 0, 0, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE))
			{
				if (WinHttpSendRequest(hRequest, 0, 0, 0, 0, 0, 0) &&
					WinHttpReceiveResponse(hRequest, 0))
				{
					WCHAR sz[0x40], * psz;
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
									delete[] Buf;
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

BOOL Exec(PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth, PCWSTR lpCmdLine = 0);

void DownloadAndExec(_In_ PCWSTR lpszServerName, _In_ PCWSTR lpszObjectName)
{
	void* pv = 0;
	ULONG cb = 0;
	if (Download(lpszServerName, lpszObjectName, &pv, &cb))
	{
		PIMAGE_NT_HEADERS pinth;
		if (0 <= RtlImageNtHeaderEx(0, pv, cb, &pinth))
		{
			Exec(pv, pinth);
		}
		delete[] pv;
	}
}

void WINAPI ep()
{
	CPP_FUNCTION;

	DownloadAndExec(L"the.earth.li", L"/~sgtatham/putty/latest/w32/putty.exe");
	DownloadAndExec(L"the.earth.li", L"/~sgtatham/putty/latest/w64/putty.exe");

	ExitProcess(0);
}
