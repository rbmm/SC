#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../ScEntry/address.h"

void WINAPI ep()
{
	CPP_FUNCTION;
	if (0 <= CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))
	{
		IApplicationActivationManager* appActivationMgr;
		if (0 <= CoCreateInstance(__uuidof(ApplicationActivationManager), 0,
			CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&appActivationMgr)))
		{
			DWORD pid;
			appActivationMgr->ActivateApplication(
				_YW(L"MicrosoftWindows.Client.Core_cw5n1h2txyewy!ScreenClipping"),
				0, AO_NONE, &pid);
			appActivationMgr->Release();
		}
		CoUninitialize();
	}
	ExitProcess(0);
}