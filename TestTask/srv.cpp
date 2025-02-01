#include "stdafx.h"

#include "print.h"

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

struct SIDS 
{
	PBYTE _ptr = (PBYTE)_buf;
	ULONG _nSids = 0;
	ULONG _cb;
	SID _buf[];

	SIDS(ULONG cb) : _cb(cb)
	{
	}

	void* operator new(size_t, void* pv)
	{
		return pv;
	}

	NTSTATUS AddSid(LONGLONG time, ULONG dwProcessId, PULONG pIndex);

	void Dump(LSA_HANDLE PolicyHandle, ENUM_SERVICE_STATUS_PROCESSW* Services, ULONG n);
};

NTSTATUS SIDS::AddSid(LONGLONG time, ULONG dwProcessId, PULONG pIndex)
{
	CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwProcessId };
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	NTSTATUS status;
	HANDLE hProcess, hToken = 0;
	if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid)))
	{
		KERNEL_USER_TIMES times;
		if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessTimes, &times, sizeof(times), 0)))
		{
			if (times.CreateTime.QuadPart < time)
			{
				status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
			}
			else
			{
				// probably new process created with same id
				status = STATUS_PROCESS_IS_TERMINATING;
			}
		}
		
		NtClose(hProcess);

		if (0 <= status)
		{
			union {
				PVOID pv;
				PTOKEN_USER ptu;
			};

			ULONG rcb;
			status = NtQueryInformationToken(hToken, TokenUser, pv = _ptr, _cb, &rcb);

			NtClose(hToken);

			if (0 <= status)
			{
				ULONG i = 0;
				PSID Sid = _buf, UserSid = ptu->User.Sid;
				if (rcb = _nSids)
				{
					do 
					{
						if (RtlEqualSid(Sid, UserSid))
						{
							// such sid already exist
							*pIndex = i;
							return STATUS_SUCCESS;
						}

						(ULONG_PTR&)Sid += RtlLengthSid(Sid);

					} while (i++, --rcb);
				}
				// new Sid

				if (_ptr != Sid)
				{
					__debugbreak();
				}

				RtlCopySid(_cb, Sid, UserSid);
				*pIndex = _nSids++, _ptr += (rcb = RtlLengthSid(Sid)), _cb -= rcb;
			}
		}
	}

	return status;
}

void SIDS::Dump(LSA_HANDLE PolicyHandle, ENUM_SERVICE_STATUS_PROCESSW* Services, ULONG n)
{
	if (ULONG i = _nSids)
	{
		PVOID pv = alloca(i * sizeof(void*));
		PSID *Sids = (PSID *)pv;

		PSID sid = _buf;
		do 
		{
			*Sids++ = sid;
			(ULONG_PTR&)sid += RtlLengthSid(sid);
		} while (--i);

		PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;
		PLSA_TRANSLATED_NAME Names = 0;

		if (0 <= LsaLookupSids(PolicyHandle, _nSids, (PSID *)pv, &ReferencedDomains, &Names))
		{
			do 
			{
				int index = Services->ServiceStatusProcess.dwWaitHint;
				if (0 <= index)
				{
					switch (Names[index].Use)
					{
					case SidTypeUser:
					case SidTypeGroup:
					case SidTypeAlias:
					case SidTypeWellKnownGroup:
					case SidTypeComputer:
						ULONG DomainIndex = Names[index].DomainIndex;
						UNICODE_STRING us = {}, *Domain = &us;
						if (DomainIndex < ReferencedDomains->Entries)
						{
							Domain = &ReferencedDomains->Domains[DomainIndex].Name;
						}

						DbgPrint("%x \"%ws\" (\"%ws\") \"%wZ\\%wZ\"\r\n", 
							Services->ServiceStatusProcess.dwProcessId,
							Services->lpServiceName,
							Services->lpDisplayName,
							Domain, &Names[index].Name);
						break;
					}
				}

			} while (Services++, --n);
		}

		LsaFreeMemory(ReferencedDomains);
		LsaFreeMemory(Names);
	}
}

NTSTATUS PrintSrvAccount(SC_HANDLE hSCManager, 
						 PCWSTR lpServiceName, 
						 QUERY_SERVICE_CONFIGW* lpServiceConfig,
						 DWORD cbBufSize)
{
	HRESULT hr;

	if (SC_HANDLE hService = HR(hr, OpenServiceW(hSCManager, lpServiceName, SERVICE_QUERY_CONFIG)))
	{
		HR(hr, QueryServiceConfigW(hService, lpServiceConfig, cbBufSize, &cbBufSize));

		CloseServiceHandle(hService);

		if (S_OK == hr)
		{
			DbgPrint("\tStartName = \"%ws\"\r\n", lpServiceConfig->lpServiceStartName);
		}
	}

	return hr;
}

HRESULT List_Services()
{
	union NT_OS_VER 
	{
		ULONG FullVersion;
		struct  
		{
			USHORT Build;
			union {
				USHORT Version;
				struct  
				{
					UCHAR Minor;
					UCHAR Major;
				};
			};
		};

		NT_OS_VER()
		{
			ULONG M, m, b;
			RtlGetNtVersionNumbers(&M, &m, &b);
			Build = (USHORT)b;
			Minor = (UCHAR)m;
			Major = (UCHAR)M;
		}	
	} nt_ver;

	ULONG cbBytesNeeded, ResumeHandle = 0, n, i;

	DWORD dwServiceType = nt_ver.Version < _WIN32_WINNT_WIN10 ? 
		SERVICE_WIN32|SERVICE_ADAPTER|SERVICE_DRIVER|SERVICE_INTERACTIVE_PROCESS : SERVICE_TYPE_ALL;

	enum { cb_buf = 0x10000, cb_b2 = 0x2000, cb_s = sizeof(SIDS) + 64*SECURITY_MAX_SID_SIZE };
	
	HRESULT hr = E_OUTOFMEMORY;

	if (PBYTE lpServices = new BYTE[cb_buf + cb_b2 + cb_s])
	{
		QUERY_SERVICE_CONFIGW* lpServiceConfig = (QUERY_SERVICE_CONFIGW*)RtlOffsetToPointer(lpServices, cb_buf);
		SIDS* pSids = new(RtlOffsetToPointer(lpServiceConfig, cb_b2)) SIDS(cb_s);

		if (SC_HANDLE hSCManager = HR(hr, OpenSCManagerW(0, 0, SC_MANAGER_ENUMERATE_SERVICE)))
		{
			LSA_HANDLE PolicyHandle;
			OBJECT_ATTRIBUTES oa = { sizeof(oa) };
			if (0 <= (hr = LsaOpenPolicy(0, &oa, POLICY_LOOKUP_NAMES, &PolicyHandle)))
			{
				do 
				{
					union {
						LARGE_INTEGER time;
						FILETIME ft;
					};
					
					GetSystemTimeAsFileTime(&ft);

					switch (hr = BOOL_TO_ERROR(EnumServicesStatusExW(hSCManager, 
						SC_ENUM_PROCESS_INFO, dwServiceType, SERVICE_STATE_ALL, 
						lpServices, cb_buf, &cbBytesNeeded, &n, &ResumeHandle, 0)))
					{
					case NOERROR:
					case ERROR_MORE_DATA:
						if (i = n)
						{
							ENUM_SERVICE_STATUS_PROCESSW* Services = (ENUM_SERVICE_STATUS_PROCESSW*)lpServices;

							do 
							{
								Services->ServiceStatusProcess.dwWaitHint = (ULONG)-1; // until no sid

								if (Services->ServiceStatusProcess.dwProcessId &&
									SERVICE_RUNNING == Services->ServiceStatusProcess.dwCurrentState)
								{
									if (0 > pSids->AddSid(time.QuadPart,
										Services->ServiceStatusProcess.dwProcessId, 
										&Services->ServiceStatusProcess.dwWaitHint))
									{
										// service terminated or access denied, or too many sids, or some error
										PrintSrvAccount(hSCManager, 
											Services->lpServiceName, 
											lpServiceConfig,
											cb_b2);
									}
								}
							} while (Services++, --i);

							pSids->Dump(PolicyHandle, (ENUM_SERVICE_STATUS_PROCESSW*)lpServices, n);
						}
						break;
					}
				} while (ERROR_MORE_DATA == hr);

				LsaClose(PolicyHandle);
			}

			CloseServiceHandle(hSCManager);
		}

		delete [] lpServices;
	}

	DbgPrint("List_Services=%x\r\n", hr);

	if (hr)
	{
		PrintError(hr);
	}

	return hr;
}