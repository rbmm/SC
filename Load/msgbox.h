#pragma once

int CustomMessageBox(HWND hWnd, PCWSTR lpText, PCWSTR lpszCaption, UINT uType);
int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR lpCaption);
HMODULE GetNtMod();
ULONG GetLastErrorEx(ULONG dwError = GetLastError());
