#include "stdafx.h"

#include "print.h"

PCSTR GetLogonTypeName(ULONG LogonType, PSTR buf, ULONG cch)
{
#define CASE_LT(x) case x: return #x;

	switch(LogonType)
	{
		CASE_LT(UndefinedLogonType);
		CASE_LT(Interactive);
		CASE_LT(Network);
		CASE_LT(Batch);
		CASE_LT(Service);
		CASE_LT(Proxy);
		CASE_LT(Unlock);
		CASE_LT(NetworkCleartext);
		CASE_LT(NewCredentials);
		CASE_LT(RemoteInteractive);
		CASE_LT(CachedInteractive);
		CASE_LT(CachedRemoteInteractive);
		CASE_LT(CachedUnlock);
	}

	sprintf_s(buf, cch, "[%x]", LogonType);
	return buf;
}

NTSTATUS ListUsers()
{
	ULONG LogonSessionCount;
	PLUID LogonSessionList;
	NTSTATUS status = LsaEnumerateLogonSessions(&LogonSessionCount, &LogonSessionList);

	if (0 <= status && LogonSessionCount)
	{
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
		LogonSessionList += LogonSessionCount;
		do 
		{
			PSECURITY_LOGON_SESSION_DATA pLogonSessionData;

			if (0 <= LsaGetLogonSessionData(--LogonSessionList, &pLogonSessionData))
			{
				if (PSID Sid = pLogonSessionData->Sid)
				{
					if (SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT + 2 == *RtlSubAuthorityCountSid(Sid) &&
						SECURITY_NT_NON_UNIQUE == *RtlSubAuthoritySid(Sid, 0) &&
						!memcmp(RtlIdentifierAuthoritySid(Sid), &NtAuthority, sizeof(SID_IDENTIFIER_AUTHORITY)))
					{
						WCHAR buf[SECURITY_MAX_SID_STRING_CHARACTERS];
						UNICODE_STRING us = { 0, sizeof(buf), buf};
						RtlConvertSidToUnicodeString(&us, Sid, FALSE);

						char lt[16];
						DbgPrint("%x {%08x-%08x} %x %hs %wZ \"%wZ\" \"%wZ\\%wZ\" %wZ\r\n", 
							pLogonSessionData->Session,
							pLogonSessionData->LogonId.HighPart,
							pLogonSessionData->LogonId.LowPart,
							pLogonSessionData->UserFlags,
							GetLogonTypeName(pLogonSessionData->LogonType, lt, _countof(lt)),
							pLogonSessionData->AuthenticationPackage,
							pLogonSessionData->LogonServer,
							pLogonSessionData->LogonDomain,
							pLogonSessionData->UserName,
							&us);
					}
				}

				LsaFreeReturnBuffer(pLogonSessionData);
			}

		} while (--LogonSessionCount);
	}

	LsaFreeReturnBuffer(LogonSessionList);

	return status;
}