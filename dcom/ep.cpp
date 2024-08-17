#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "..\ScEntry\asmfunc.h"

NTSTATUS IsCredentialUIBroker(_In_ PCWSTR lpApplicationName)
{
	HANDLE hKey;

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	RtlInitUnicodeString(&ObjectName, L"\\Registry\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{924DC564-16A6-42EB-929A-9A61FA7DA06F}\\LocalServer32");

	if (0 <= ZwOpenKey(&hKey, KEY_READ, &oa))
	{
		RtlInitUnicodeString(&ObjectName, L"ServerExecutable");

		ULONG cb;
		union {
			KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 kvpi;
			UCHAR buf[0x200];
		};

		NTSTATUS status = ZwQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, buf, sizeof(buf), &cb);

		NtClose(hKey);

		if (0 <= status)
		{
			PWSTR pwz = 0;
			ULONG cch = 0;

			switch (kvpi.Type)
			{
			case REG_SZ:
				pwz = (PWSTR)kvpi.Data;

			case REG_EXPAND_SZ:
				if (kvpi.DataLength && 
					!(kvpi.DataLength & (__alignof(WCHAR) - 1)) &&
					!*(PCWSTR)RtlOffsetToPointer(kvpi.Data, kvpi.DataLength - sizeof(WCHAR)))
				{
					if (pwz)
					{
						return !wcscmp(lpApplicationName, pwz);
					}

					while (cch = ExpandEnvironmentStringsW((PWSTR)kvpi.Data, pwz, cch))
					{
						if (pwz)
						{
							return !wcscmp(lpApplicationName, pwz);
						}

						pwz = (PWSTR)alloca(cch * sizeof(WCHAR));
					}
				}
			}
		}
	}

	return FALSE;
}

HANDLE GetToken()ASM_FUNCTION;
void SetToken(HANDLE hToken)ASM_FUNCTION;

BOOL
WINAPI
hook_CreateProcessAsUserW(
	_In_opt_ HANDLE hToken,
	_In_opt_ LPCWSTR lpApplicationName,
	_Inout_opt_ LPWSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCWSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOW lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
)
{
	STARTUPINFOW si{ sizeof(si) };

	HANDLE hMyToken = 0;
	BOOL fRestoreToken = FALSE;
	HANDLE hNewToken = 0;

	if (hToken && lpApplicationName && IsCredentialUIBroker(lpApplicationName))
	{
		OpenThreadToken(NtCurrentThread(), TOKEN_IMPERSONATE, TRUE, &hMyToken);

		if (DuplicateToken(GetToken(), ::SecurityImpersonation, &hNewToken))
		{
			if (0 <= ZwSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken)))
			{
				fRestoreToken = TRUE;
				hToken = GetToken();
				si.lpDesktop = const_cast<PWSTR>(L"Winsta0\\Winlogon");
				lpStartupInfo = &si;
		
				if (IsDebuggerPresent()) __debugbreak();
			}
		
			NtClose(hNewToken);
		}
	}

	BOOL fOk = CreateProcessAsUserW(
		hToken,
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);

	if (fRestoreToken)
	{
		NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hMyToken, sizeof(hMyToken));
	}

	return fOk;
}

PVOID Assign(void** pp, void* p)
{
	ULONG op;
	if (VirtualProtect(pp, sizeof(PVOID), PAGE_READWRITE, &op))
	{
		p = InterlockedExchangePointer(pp, p);
		VirtualProtect(pp, sizeof(PVOID), op, &op);

		return p;
	}

	return FALSE;
}

void DoHook(void** pIAT, HANDLE hEventLow, HANDLE hEventHigh)
{
	if (PVOID pv = Assign(pIAT, hook_CreateProcessAsUserW))
	{
		BOOL f = SetEvent(hEventHigh);

		if (f)
		{
			WaitForSingleObject(hEventLow, INFINITE);
		}

		Assign(pIAT, pv);
	}
}

void** FindApi(HMODULE hmod, PCSTR Name);

void WINAPI ep(ULONG dwProcessId, HANDLE hEventLow, HANDLE hEventHigh)
{
	CPP_FUNCTION;

	if (IsDebuggerPresent()) __debugbreak();

	if (HMODULE hmod = GetModuleHandleW(L"rpcss.dll"))
	{
		if (void** pIAT = FindApi(hmod, "CreateProcessAsUserW"))
		{
			if (HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId))
			{
				if (DuplicateHandle(hProcess, hEventLow, NtCurrentProcess(), &hEventLow, SYNCHRONIZE, 0, 0))
				{
					if (DuplicateHandle(hProcess, hEventHigh, NtCurrentProcess(), &hEventHigh, EVENT_MODIFY_STATE, 0, 0))
					{
						HANDLE hToken;
						if (OpenProcessToken(hProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
						{
							SetToken(hToken);

							DoHook(pIAT, hEventLow, hEventHigh);

							NtClose(hToken);
						}

						NtClose(hEventHigh);
					}

					NtClose(hEventLow);
				}

				NtClose(hProcess);
			}
		}
	}
}