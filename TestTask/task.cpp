#include "stdafx.h"

#include "print.h"

#define CASE_LT(x) case x: return #x;
PCSTR GetStateName(TASK_STATE ts, PSTR buf, ULONG cch)
{
	switch (ts)
	{
		CASE_LT(TASK_STATE_UNKNOWN);
		CASE_LT(TASK_STATE_DISABLED);
		CASE_LT(TASK_STATE_QUEUED);
		CASE_LT(TASK_STATE_READY);
		CASE_LT(TASK_STATE_RUNNING);
	}

	sprintf_s(buf, cch, "[%x]", ts);
	return buf;
}

HRESULT CreateTask_I(PWSTR xml)
{
	HRESULT hr;
	if (0 <= (hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE)))
	{
		ITaskService *pService;
		if (0 <= (hr = CoCreateInstance( __uuidof(TaskScheduler),
			0, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pService))))
		{
			VARIANT v {};
			ITaskFolder *pRootFolder = 0;

			0 <= (hr = pService->Connect(v, v, v, v)) && 
				0 <= (hr = pService->GetFolder( const_cast<PWSTR>( L"\\") , &pRootFolder ));

			pService->Release();

			if (0 <= hr)
			{
				VARIANT userId {VT_BSTR}, password{}, sddl{};

				userId.bstrVal = SysAllocString(L"S-1-5-32-544");

				pRootFolder->RegisterTask(const_cast<PWSTR>(L"cmd"), 
					xml, TASK_CREATE_OR_UPDATE, userId, password, 
					TASK_LOGON_GROUP, sddl, 0);//

				SysFreeString(userId.bstrVal);

				pRootFolder->Release();
			}
		}

		CoUninitialize();
	}

	return hr;
}

NTSTATUS CreateTask(PCWSTR fmt)
{
	NTSTATUS hr;
	WCHAR cmd[0x100];
	PWSTR xml = 0;

	if (HR(hr, GetEnvironmentVariableW(L"comspec", cmd, _countof(cmd))))
	{
		hr = STATUS_UNSUCCESSFUL;

		int len = 0;
		while (0 < (len = _snwprintf(xml, len, fmt, cmd)))
		{
			if (xml)
			{
				hr = STATUS_SUCCESS;
				break;
			}

			if (!(xml = new WCHAR[++len]))
			{
				break;
			}
		}
	}

	if (S_OK == hr)
	{
		hr = CreateTask_I(xml);
	}

	if (xml)
	{
		delete [] xml;
	}

	return hr;
}

extern const char xml_begin[], xml_end[];

NTSTATUS CreateTask()
{
	PWSTR fmt = 0;
	ULONG cch = 0;
	ULONG cb = RtlPointerToOffset(xml_begin, xml_end);

	while (cch = MultiByteToWideChar(CP_UTF8, 0, xml_begin, cb, fmt, cch))
	{
		if (fmt)
		{
			fmt[cch] = 0;
			return CreateTask(fmt);
		}

		fmt = (PWSTR)alloca(sizeof(WCHAR) * (1 + cch));
	}

	return HRESULT_FROM_NT(STATUS_INTERNAL_ERROR);
}

void ListFolder(ITaskFolder *pRootFolder, PCSTR prefix)
{
	union {
		ITaskFolderCollection* pFolders;
		IRegisteredTaskCollection* pTaskCollection;
	};

	union {
		ITaskFolder *pFolder;
		IRegisteredTask* pRegisteredTask;
	};

	HRESULT hr;

	VARIANT v { VT_I4 };

	BSTR Name;

	if (0 <= pRootFolder->get_Name(&Name))
	{
		DbgPrint("%hs[\"%ws\"]\r\n", prefix, Name);
		SysFreeString(Name);
	}

	if (0 <= (hr = pRootFolder->GetTasks( TASK_ENUM_HIDDEN , &pTaskCollection )))
	{
		if (0 <= (hr = pTaskCollection->get_Count(&v.lVal)))
		{
			if (v.lVal)
			{
				do 
				{
					if (0 <= (hr = pTaskCollection->get_Item( v, &pRegisteredTask )))
					{
						TASK_STATE taskState;
						char sz[16];

						if (0 <= (hr = pRegisteredTask->get_State(&taskState)) &&
							0 <= (hr = pRegisteredTask->get_Name(&Name)) )
						{
							DbgPrint("%hs\t[%hs]: \"%ws\"\r\n", prefix, GetStateName(taskState, sz, _countof(sz)), Name);
							SysFreeString(Name);
						}

						pRegisteredTask->Release();
					}

				} while (--v.lVal);
			}
		}

		pTaskCollection->Release();
	}

	if (0 > *--prefix)
	{
		DbgPrint("!! too deep\r\n");
		return ;
	}

	if (0 <= (hr = pRootFolder->GetFolders( 0, &pFolders )))
	{
		if (0 <= (hr = pFolders->get_Count(&v.lVal)))
		{
			if (v.lVal)
			{
				do 
				{
					if (0 <= (hr = pFolders->get_Item( v, &pFolder )))
					{
						ListFolder(pFolder, prefix);
						pFolder->Release();
					}

				} while (--v.lVal);
			}
		}

		pTaskCollection->Release();
	}
}

HRESULT ListTask()
{
	HRESULT hr;
	if (0 <= (hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE)))
	{
		ITaskService *pService;
		if (0 <= (hr = CoCreateInstance( __uuidof(TaskScheduler),
			0, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pService))))
		{
			VARIANT v {};
			ITaskFolder *pRootFolder = 0;

			0 <= (hr = pService->Connect(v, v, v, v)) && 
				0 <= (hr = pService->GetFolder( const_cast<PWSTR>( L"\\") , &pRootFolder ));

			pService->Release();

			if (0 <= hr)
			{
				char prefix[64];
				memset(prefix, '\t', _countof(prefix));
				prefix[_countof(prefix) - 1] = 0;
				prefix[0] = -1;
				ListFolder(pRootFolder, prefix + _countof(prefix) - 1);
				pRootFolder->Release();
			}
		}

		CoUninitialize();
	}

	return hr;
}
