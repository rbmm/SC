#include "stdafx.h"

_NT_BEGIN

LRESULT CALLBACK MyScp(HWND hWnd, UINT uMsg, WPARAM wParam,
	LPARAM lParam, UINT_PTR /*uIdSubclass*/, DWORD_PTR /*dwRefData*/)
{
	if (WM_SHOWWINDOW == uMsg)
	{
		RemoveWindowSubclass(hWnd, MyScp, 0);
		_LDR_DATA_TABLE_ENTRY* ldte;
		if (0 <= LdrFindEntryForAddress(&__ImageBase, &ldte))
		{
			int len = 0;
			PWSTR psz = 0;
			while (0 < (len = _snwprintf(psz, len, L"I am here: %p \"%wZ\"\r\n\r\n", ldte->DllBase, &ldte->FullDllName)))
			{
				if (psz)
				{
					DefSubclassProc(hWnd, WM_SETTEXT, 0, (LPARAM)psz);
					break;
				}

				psz = (PWSTR)alloca(++len * sizeof(WCHAR));
			}
		}
	}

	return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

HHOOK _G_hhk;

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HCBT_CREATEWND)
	{
		CBT_CREATEWND* pccw = reinterpret_cast<CBT_CREATEWND*>(lParam);

		PCWSTR lpszClass = pccw->lpcs->lpszClass;
		if (!IS_INTRESOURCE(lpszClass) && !_wcsicmp(WC_EDITW, lpszClass))
		{
			SetWindowSubclass((HWND)wParam, MyScp, 0, 0);
			UnhookWindowsHookEx(_G_hhk);
			_G_hhk = 0;
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

BOOLEAN WINAPI DllMain(HMODULE hmod, DWORD dwReason, PVOID)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hmod);
		_G_hhk = SetWindowsHookExW(WH_CBT, CBTProc, hmod, GetCurrentThreadId());
		break;
	case DLL_PROCESS_DETACH:
		if (_G_hhk)
		{
			UnhookWindowsHookEx(_G_hhk);
			_G_hhk = 0;
		}
		break;
	}

	return TRUE;
}

_NT_END