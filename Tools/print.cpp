#include "stdafx.h"

#include "print.h"

#define _malloca_s(size) ((size) < _ALLOCA_S_THRESHOLD ? alloca(size) : LocalAlloc(LMEM_FIXED, size))

inline void _freea_s(PVOID pv)
{
	PNT_TIB tib = (PNT_TIB)NtCurrentTeb();
	if (pv < tib->StackLimit || tib->StackBase <= pv) LocalFree(pv);
}

void PutChars(PCWSTR pwz, ULONG cch)
{
	if (PrintInfo* ppi = PrintInfo::get())
	{
		PSTR buf = 0;
		ULONG len = 0;
		while (len = WideCharToMultiByte(ppi->_G_CodePage, 0, pwz, cch, buf, len, 0, 0))
		{
			if (buf)
			{
				break;
			}

			if (!(buf = (PSTR)_malloca_s(len)))
			{
				break;
			}
		}

		if (IsDebuggerPresent())
		{
			ULONG_PTR params[] = { cch, (ULONG_PTR)pwz, len, (ULONG_PTR)buf };
			RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, _countof(params), params);
		}

		if (ppi->_G_hFile)
		{
			if (ppi->_G_bConsole)
			{
				WriteConsoleW(ppi->_G_hFile, pwz, cch, &cch, 0);
			}
			else
			{
				WriteFile(ppi->_G_hFile, buf, len, &len, 0);

			}
		}

		if (buf)
		{
			_freea_s(buf);
		}
	}
}

void PrintWA_v(PCWSTR format, ...)
{
	va_list ap;
	va_start(ap, format);

	PWSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnwprintf(buf, len, format, ap)))
	{
		if (buf)
		{
			PutChars(buf, len);
			break;
		}

		++len;
		if (!(buf = (PWSTR)_malloca_s(len * sizeof(WCHAR))))
		{
			break;
		}
	}

	if (buf)
	{
		_freea_s(buf);
	}

	va_end(ap);
}

HRESULT PrintError(HRESULT dwError)
{
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		lpSource = GetModuleHandle(L"ntdll");
	}

	PWSTR lpText;
	if (ULONG cch = FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		PutChars(lpText, cch);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return dwError;
}

void InitPrintf()
{
	if (PrintInfo* ppi = PrintInfo::get())
	{
		ppi->_G_CodePage = GetConsoleOutputCP();
		ppi->_G_hFile = 0;

		if (HANDLE hFile = GetStdHandle(STD_OUTPUT_HANDLE))
		{
			ppi->_G_hFile = hFile;
			FILE_FS_DEVICE_INFORMATION ffdi;
			IO_STATUS_BLOCK iosb;
			if (0 <= NtQueryVolumeInformationFile(hFile, &iosb, &ffdi, sizeof(ffdi), FileFsDeviceInformation))
			{
				switch (ffdi.DeviceType)
				{
				case FILE_DEVICE_CONSOLE:
					ppi->_G_bConsole = TRUE;
					break;
				}
			}
		}
	}
}