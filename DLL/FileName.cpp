#include "stdafx.h"

#include "rtlframe.h"

struct FICON
{
	HICON hIcon = 0;
};

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HCBT_CREATEWND)
	{
		CBT_CREATEWND* pccw = reinterpret_cast<CBT_CREATEWND*>(lParam);

		if (pccw->lpcs->lpszClass == WC_DIALOG)
		{
			if (FICON* p = RTL_FRAME<FICON>::get())
			{
				SendMessageW((HWND)wParam, WM_SETICON, ICON_SMALL, (LPARAM)p->hIcon);
			}
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

enum ZBID
{
	ZBID_DEFAULT = 0,
	ZBID_DESKTOP = 1,
	ZBID_UIACCESS = 2,
	ZBID_IMMERSIVE_IHM = 3,
	ZBID_IMMERSIVE_NOTIFICATION = 4,
	ZBID_IMMERSIVE_APPCHROME = 5,
	ZBID_IMMERSIVE_MOGO = 6,
	ZBID_IMMERSIVE_EDGY = 7,
	ZBID_IMMERSIVE_INACTIVEMOBODY = 8,
	ZBID_IMMERSIVE_INACTIVEDOCK = 9,
	ZBID_IMMERSIVE_ACTIVEMOBODY = 10,
	ZBID_IMMERSIVE_ACTIVEDOCK = 11,
	ZBID_IMMERSIVE_BACKGROUND = 12,
	ZBID_IMMERSIVE_SEARCH = 13,
	ZBID_GENUINE_WINDOWS = 14,
	ZBID_IMMERSIVE_RESTRICTED = 15,
	ZBID_SYSTEM_TOOLS = 16,

	//Windows 10+
	ZBID_LOCK = 17,
	ZBID_ABOVELOCK_UX = 18
};

EXTERN_C
WINUSERAPI
HWND
WINAPI
CreateWindowInBand(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam,
	_In_opt_ ZBID dwBand);

struct LARGE_STRING {
	ULONG Length;
	ULONG MaximumLength;
	PCWSTR  Buffer;
};

struct ZCWS
{
	PVOID ReturnAddress;
	_In_ __declspec(align(__alignof(PVOID))) DWORD dwExStyle;
	_In_opt_ LARGE_STRING* lpClassName;
	_In_opt_ LARGE_STRING* lpClassName2;
	_In_opt_ LARGE_STRING* lpWindowName;
	_In_ __declspec(align(__alignof(PVOID))) DWORD dwStyle;
	_In_ __declspec(align(__alignof(PVOID))) int X;
	_In_ __declspec(align(__alignof(PVOID))) int Y;
	_In_ __declspec(align(__alignof(PVOID))) int nWidth;
	_In_ __declspec(align(__alignof(PVOID))) int nHeight;
	_In_opt_ HWND hWndParent;
	_In_opt_ HMENU hMenu;
	_In_opt_ HINSTANCE hInstance;
	_In_opt_ LPVOID lpParam;
	_In_opt_ __declspec(align(__alignof(PVOID))) ZBID dwBand;
};

NTSTATUS CreateAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE secret, _In_ ULONG cb)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, secret, cb, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

void ShowFlag(LARGE_STRING* lpWindowName)
{
	_LDR_DATA_TABLE_ENTRY* ldte;
	if (0 <= LdrFindEntryForAddress(&__ImageBase, &ldte))
	{
		BCRYPT_KEY_HANDLE hKey;
		union {
			UCHAR secret[32];
			WCHAR szFlag[0x80];
		};
		ULONG s = sizeof(secret);
		
		//ldte->TimeDateStamp = 0x684a7c9d; //

		if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, (PBYTE)&ldte->TimeDateStamp, sizeof(ULONG), secret, &s))
		{
			if (0 <= CreateAesKey(&hKey, secret, s))
			{
				static const UCHAR enc[] = {
					0xA7, 0xF7, 0xB1, 0x9A, 0xDC, 0x2C, 0xEB, 0x75,
					0x94, 0x2D, 0x1F, 0x72, 0xAA, 0xE6, 0x3C, 0x1F,
					0x9C, 0x92, 0x5C, 0x7B, 0x22, 0xE0, 0x99, 0x83,
					0x21, 0x48, 0xCE, 0x3F, 0x2F, 0xB4, 0x71, 0xE4,
					0x41, 0xE9, 0x45, 0xFB, 0xD1, 0xEB, 0x4C, 0x09,
					0x55, 0xEB, 0x45, 0xA3, 0x22, 0x46, 0x4A, 0x4F,
					0x4C, 0x70, 0x2A, 0x3C, 0x61, 0xF0, 0x1E, 0x0E,
					0xF5, 0x50, 0xD9, 0xC5, 0xAC, 0xF2, 0x6C, 0x3C,
					0x2F, 0x66, 0xD7, 0x5E, 0x24, 0xF2, 0x16, 0xA4,
					0x58, 0x62, 0x30, 0xFB, 0x1A, 0x48, 0x81, 0xE0,
					0xF1, 0x80, 0x01, 0x87, 0xC7, 0xEA, 0x5B, 0x03,
					0xE6, 0xBA, 0xB8, 0xC2, 0x4A, 0xAB, 0x0B, 0x66,
				};

				ULONG cb = lpWindowName->MaximumLength;
				PBYTE buf = (PBYTE)alloca(cb);

				if (0 <= BCryptDecrypt(hKey, (PBYTE)enc, sizeof(enc), 0, 0, 0, buf,
					cb, &s, BCRYPT_BLOCK_PADDING))
				{
					memcpy((void*)lpWindowName->Buffer, buf, s);
					lpWindowName->Length = s - sizeof(WCHAR);
					lpWindowName->MaximumLength = s;
				}
				BCryptDestroyKey(hKey);
			}
		}
	}
}

LONG NTAPI MyVexHandler(::PEXCEPTION_POINTERS ExceptionInfo)
{
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
	::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

	if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == (PVOID)ContextRecord->Dr3)
	{
		if (IsDebuggerPresent()) __debugbreak();

		if ((ULONG_PTR)WC_DIALOG == ContextRecord->Rdx && (ULONG_PTR)WC_DIALOG == ContextRecord->R8)
		{
			ULONG_PTR lpWindowName = ContextRecord->R9;
			if (lpWindowName > MAXUSHORT)
			{
				ZCWS* stack = (ZCWS*)ContextRecord->Rsp;

				if (!stack->hWndParent)
				{
					stack->dwBand = ZBID_ABOVELOCK_UX;
					ShowFlag((LARGE_STRING*)lpWindowName);
				}
			}
		}

		ContextRecord->Dr3 = 0;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL IsVersionOk()
{
	ULONG M, m, b;
	RtlGetNtVersionNumbers(&M, &m, &b);
	if (M < (_WIN32_WINNT_WIN10 >> 8))
	{
		WCHAR sz[64];
		swprintf_s(sz, _countof(sz), L"ver = %u.%u.%u", M, m, b & 0x0fffffff);
		MessageBoxW(0, L"you need windows 10+ version", sz, MB_ICONWARNING);
		return FALSE;
	}

	return TRUE;
}

void ShowMsg(_In_ CONST MSGBOXPARAMSW* lpmbp)
{
	HHOOK hhk = 0;
	RTL_FRAME<FICON> frame;

	if (0 <= LoadIconWithScaleDown(0, IDI_INFORMATION,
		GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &frame.hIcon))
	{
		hhk = SetWindowsHookExW(WH_CBT, CBTProc, 0, GetCurrentThreadId());
	}

	MessageBoxIndirectW(lpmbp);

	if (hhk) UnhookWindowsHookEx(hhk);

	if (frame.hIcon) DestroyIcon(frame.hIcon);
}

void fmb()
{
	PostQuitMessage(0);
	MessageBoxW(0, 0, 0, 0);
	MSG msg;
	while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE));
}

ULONG WINAPI DemoThread(HANDLE )
{
	if (IsVersionOk())
	{
		WCHAR FileName[0x100]= L"Loaded as: ";
		ULONG len = (ULONG)wcslen(FileName);
		if (GetModuleFileNameW((HMODULE)&__ImageBase, FileName + len, _countof(FileName) - len))
		{
			struct __declspec(uuid("1FC98BCA-1BA9-4397-93F9-349EAD41E057")) RtlpAddVectoredHandler;

			union {
				PVOID pvfn;
				NTSTATUS(NTAPI* RtlSetProtectedPolicy)(
					_In_ const GUID* PolicyGuid,
					_In_ ULONG_PTR PolicyValue,
					_Out_ PULONG_PTR OldPolicyValue
					);
			};

			if (HMODULE hmod = GetModuleHandleW(L"win32u"))
			{
				CONTEXT ctx = {};
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				ctx.Dr7 = 0x440;
				ULONG_PTR up = (ULONG_PTR)GetProcAddress(hmod, ("NtUserCreateWindowEx"));
				if (ctx.Dr3 = up)
				{
					if (hmod = GetModuleHandleW(L"ntdll"))
					{
						if (pvfn = GetProcAddress(hmod, ("RtlSetProtectedPolicy")))
						{
							ULONG_PTR OldValue;
							RtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), 0, &OldValue);

							NTSTATUS status = STATUS_UNSUCCESSFUL;

							if (PVOID VectoredHandlerHandle = RtlAddVectoredExceptionHandler(TRUE, (MyVexHandler)))
							{
								if (0 <= (status = ZwSetContextThread(NtCurrentThread(), &ctx)))
								{
									fmb();

									ctx.Dr3 = up;

									ZwSetContextThread(NtCurrentThread(), &ctx);

									MSGBOXPARAMSW mbp = {
										sizeof(mbp),
										0,
										(HINSTANCE)&__ImageBase,
										FileName,
										L"***** ***** !! FLAG not captured !! ***** *****",
										MB_USERICON | MB_OK,
										MAKEINTRESOURCE(1)
									};

									ShowMsg(&mbp);

									ctx.Dr3 = 0;
									ctx.Dr7 = 0x400;
									ZwSetContextThread(NtCurrentThread(), &ctx);
								}
								RtlRemoveVectoredExceptionHandler(VectoredHandlerHandle);
							}

							RtlSetProtectedPolicy(&__uuidof(RtlpAddVectoredHandler), OldValue, &OldValue);
						}
					}
				}
			}
		}
	}

	FreeLibraryAndExitThread((HMODULE)&__ImageBase, 0);
}

BOOLEAN WINAPI DllMain(HMODULE hmod, DWORD dwReason, HANDLE hThread)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hmod);
		//if (GetShellWindow() && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCWSTR)hmod, &hmod))
		{
			if (hThread = CreateThread(0, 0, DemoThread, 0, 0, 0))
			{
				CloseHandle(hThread);
				break;
			}
			//FreeLibrary(hmod);
		}
		return FALSE;
	}

	return TRUE;
}