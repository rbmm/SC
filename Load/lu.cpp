#include "stdafx.h"

#include "resource.h"
#include "msgbox.h"
#include "../InjLfmACG/inject.h"

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

NTSTATUS InjectToSelf(_In_ PCWSTR lpFileName, _Out_ PVOID* pImageBase);

NTSTATUS InjectScACG(
	_In_ HANDLE hProcess,
	_In_ PCWSTR lpFileName,
	_Out_ PVOID* pImageBase,
	_Out_ PBOOL StatusFromRemote);

HRESULT OnBrowse(_In_ HWND hwndDlg, _Out_ PWSTR* ppszFilePath)
{
	IFileDialog* pFileOpen;

	HRESULT hr = CoCreateInstance(__uuidof(FileOpenDialog), NULL, CLSCTX_ALL, IID_PPV_ARGS(&pFileOpen));

	if (SUCCEEDED(hr))
	{
		pFileOpen->SetOptions(FOS_NOVALIDATE | FOS_NOTESTFILECREATE |
			FOS_NODEREFERENCELINKS | FOS_DONTADDTORECENT | FOS_FORCESHOWHIDDEN);

		static const COMDLG_FILTERSPEC rgSpec[] =
		{
			{ L"DLL files", L"*.DLL" }, { L"ALL files", L"*"}
		};

		if (0 <= (hr = pFileOpen->SetFileTypes(_countof(rgSpec), rgSpec)) &&
			0 <= (hr = pFileOpen->SetFileTypeIndex(1)) &&
			0 <= (hr = pFileOpen->Show(hwndDlg)))
		{
			IShellItem* pItem;
			hr = pFileOpen->GetResult(&pItem);

			if (SUCCEEDED(hr))
			{
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, ppszFilePath);
				pItem->Release();
			}
		}
		pFileOpen->Release();
	}

	return hr;
}

HRESULT OnBrowse(HWND hwndDlg, UINT nIDDlgItem)
{
	PWSTR pszFilePath;
	HRESULT hr = OnBrowse(hwndDlg, &pszFilePath);

	if (S_OK == hr)
	{
		SetDlgItemTextW(hwndDlg, nIDDlgItem, pszFilePath);
		CoTaskMemFree(pszFilePath);
	}

	return hr;
}

CHAR GetWow(SYSTEM_EXTENDED_THREAD_INFORMATION Threads[], ULONG NumberOfThreads)
{
	if (NumberOfThreads)
	{
		PCLIENT_ID ClientId = &Threads->ClientId;

		PVOID pv = 0;
		do 
		{
			PVOID Win32StartAddress = Threads++->Win32StartAddress;
			if (pv < Win32StartAddress)
			{
				pv = Win32StartAddress;
			}

		} while (--NumberOfThreads);

		if ((ULONG_PTR)pv < MAXLONG)
		{
			if (!pv)
			{
				return '#';
			}

			ClientId->UniqueThread = 0;
			HANDLE hProcess;
			OBJECT_ATTRIBUTES oa = { sizeof(oa) };
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, ClientId))
			{
				PROCESS_EXTENDED_BASIC_INFORMATION ebi = {};
				NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ebi, sizeof(ebi), 0);
				NtClose(hProcess);

				if (0 <= status)
				{
					if (!ebi.IsProtectedProcess && !ebi.IsFrozen && !ebi.IsProcessDeleting)
					{
						return ebi.IsWow64Process ? '*' : ' ';
					}
				}
			}

			return '#';
		}

		return ' ';
	}

	return '#';
}

void MakeProcessList(HWND hwnd)
{
	ComboBox_ResetContent(hwnd);

	ULONG cb = 0x80000;

	NTSTATUS status;

	do
	{
		status = STATUS_NO_MEMORY;

		if (PVOID buf = LocalAlloc(0, cb += 0x1000))
		{
			if (0 <= (status = ZwQuerySystemInformation(SystemExtendedProcessInformation, buf, cb, &cb)))
			{
				union {
					PVOID pv;
					PBYTE pb;
					PSYSTEM_PROCESS_INFORMATION pspi;
				};

				pv = buf;

				ULONG NextEntryOffset = 0;

				WCHAR sz[0x100];

				struct PROCESS_MITIGATION {
					PROCESS_MITIGATION_POLICY Policy;
					union {
						PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp;
					};
				};

				PROCESS_MITIGATION m = { ProcessDynamicCodePolicy };

				do
				{
					pb += NextEntryOffset;

					if (pspi->UniqueProcessId)
					{
						CHAR ProhibitDynamicCode = ' ';

						if (HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, (ULONG)(ULONG_PTR)pspi->UniqueProcessId))
						{
							if (0 <= NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &m, sizeof(m), 0))
							{
								ProhibitDynamicCode = m.dcp.ProhibitDynamicCode ? '!' : ' ';
							}
							NtClose(hProcess);
						}

						if (0 < swprintf_s(sz, _countof(sz), 
							L"%4x(%4x) %2x %3x %c %c %wZ",
							(ULONG)(ULONG_PTR)pspi->UniqueProcessId,
							(ULONG)(ULONG_PTR)pspi->InheritedFromUniqueProcessId,
							pspi->SessionId,
							pspi->NumberOfThreads,
							GetWow(pspi->Threads, pspi->NumberOfThreads),
							ProhibitDynamicCode,
							&pspi->ImageName))
						{
							int i = ComboBox_AddString(hwnd, sz);
							if (0 <= i)
							{
								ComboBox_SetItemData(hwnd, i, pspi->UniqueProcessId);
							}
						}
					}

				} while (NextEntryOffset = pspi->NextEntryOffset);
			}

			LocalFree(buf);
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
}

struct __declspec(uuid("178167bc-4ee3-403e-8430-a6434162db17")) WebPlatStorageCom;

struct __declspec(uuid("0d67d0a5-4736-4a43-b642-e77f2105b3e2")) IWebPlatStorageCom : public IUnknown
{
	virtual HRESULT STDAPICALLTYPE GetRPCEndpoint(PWSTR*) = 0;
};

void StartWebPlat(HWND hwnd)
{
	HRESULT hr;
	IWebPlatStorageCom* pWebCom;
	if (0 <= (hr = CoCreateInstance(__uuidof(WebPlatStorageCom), 0,
		CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_AAA, IID_PPV_ARGS(&pWebCom))))
	{
		PWSTR psz;
		if (0 <= pWebCom->GetRPCEndpoint(&psz))
		{
			CustomMessageBox(hwnd, psz, L"WebPlatStorage", MB_ICONINFORMATION);
			CoTaskMemFree(psz);
		}
		pWebCom->Release();
	}
}

void ShowResult(HWND hwnd, NTSTATUS status, void* hmod, BOOL bRemote = FALSE)
{
	if (status)
	{
		ShowErrorBox(hwnd, status, bRemote ? L"Remote" : L"Local");
	}
	else
	{
		WCHAR sz[64];
		if (bRemote)
		{
			swprintf_s(sz, _countof(sz), L"base=%p", hmod);
			CustomMessageBox(hwnd, sz, L"Remote Load !", MB_ICONINFORMATION);
		}
		else
		{
			PLDR_DATA_TABLE_ENTRY ldte;
			if (0 <= LdrFindEntryForAddress(hmod, &ldte))
			{
				swprintf_s(sz, _countof(sz), L"base=%p size=%x", hmod, ldte->SizeOfImage);
				CustomMessageBox(hwnd, ldte->FullDllName.Buffer, sz, MB_ICONINFORMATION);
			}
		}
	}
}

VOID load(HWND hwnd, HWND hwndEdit)
{
	if (ULONG len = GetWindowTextLengthW(hwndEdit))
	{
		NTSTATUS status = STATUS_NO_MEMORY;
		void* hmod = 0;

		if (PWSTR psz = new WCHAR[++len])
		{
			if (GetWindowTextW(hwndEdit, psz, len))
			{
				if (BST_CHECKED == SendDlgItemMessageW(hwnd, IDC_CHECK1, BM_GETCHECK, 0, 0))
				{
					status = InjectToSelf(psz, &hmod);
				}
				else
				{
					status = STATUS_INVALID_CID;

					int i = (int)SendDlgItemMessageW(hwnd, IDC_COMBO1, CB_GETCURSEL, 0, 0);
					if (0 <= i)
					{
						CLIENT_ID cid{};
						if (cid.UniqueProcess = (HANDLE)SendDlgItemMessageW(hwnd, IDC_COMBO1, CB_GETITEMDATA, i, 0))
						{
							HANDLE hProcess;
							OBJECT_ATTRIBUTES oa = { sizeof(oa) };
							if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid)))
							{
								PROCESS_EXTENDED_BASIC_INFORMATION ebi = {};
								
								if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ebi, sizeof(ebi), 0)))
								{
									if (ebi.IsFrozen || ebi.IsProcessDeleting)
									{
										status = STATUS_PROCESS_IS_TERMINATING;
									}
									else if (
#ifdef _WIN64
										! 

#endif // _WIN64
										ebi.IsWow64Process)
									{
										BOOL StatusFromRemote = FALSE;
										status = InjectScACG(hProcess, psz, &hmod, &StatusFromRemote);
										ShowResult(hwnd, status, hmod, StatusFromRemote);
										if (hmod && !status)
										{
											RemoteUnloadDll(hProcess, hmod);
										}
										len = 0;
									}
									else
									{
										status = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
									}
								}

								NtClose(hProcess);
							}
						}
					}

				}
			}
			delete[] psz;
		}

		if (len)
		{
			ShowResult(hwnd, status, hmod);
			if (0 <= status)
			{
				LdrUnloadDll(hmod);
			}
		}
	}
}

void OnInitDialog(HWND hwnd)
{
	HICON hi;
	if (0 <= LoadIconWithScaleDown((HINSTANCE) & __ImageBase, MAKEINTRESOURCEW(1),
		GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hi))
	{
		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hi);
	}

	SendDlgItemMessageW(hwnd, IDC_CHECK1, BM_SETCHECK, BST_CHECKED, 0);

	NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
	if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
	{
		ncm.lfStatusFont.lfQuality = CLEARTYPE_QUALITY;
		ncm.lfStatusFont.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
		wcscpy(ncm.lfStatusFont.lfFaceName, L"Courier New");

		if (HFONT hFont = CreateFontIndirect(&ncm.lfStatusFont))
		{
			SendDlgItemMessageW(hwnd, IDC_COMBO1, WM_SETFONT, (WPARAM)hFont, 0);
		}
	}
}

INT_PTR CALLBACK DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			load(hwnd, GetDlgItem(hwnd, IDC_EDIT1));
			break;

		case IDCANCEL:
			EndDialog(hwnd, lParam);
			break;

		case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
			OnBrowse(hwnd, IDC_EDIT1);
			break;

		case MAKEWPARAM(IDC_CHECK1, BN_CLICKED):
			EnableWindow(GetDlgItem(hwnd, IDC_COMBO1), BST_UNCHECKED == SendMessageW((HWND)lParam, BM_GETCHECK, 0, 0));
			break;

		case MAKEWPARAM(IDC_COMBO1, CBN_DROPDOWN):
			MakeProcessList((HWND)lParam);
			break;
		}
		break;

	case WM_NOTIFY:
		if (IDC_SYSLINK1 == wParam)
		{
			PNMLINK p = (PNMLINK)reinterpret_cast<PNMLINK>(lParam);
			switch (p->hdr.code)
			{
			case NM_CLICK:
				SetFocus(0);
				StartWebPlat(hwnd);
				break;
			}
		}
		break;

	case WM_INITDIALOG:
		OnInitDialog(hwnd);
		break;
	}
	return 0;
}

void ep(void*)
{
	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);
	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		DialogBoxParamW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, DlgProc, 0);
		CoUninitialize();
	}

	ExitProcess(0);
}
