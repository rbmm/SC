#include "stdafx.h"

#include "print.h"

NTSTATUS List_all_running_processes();
NTSTATUS DumpProcessThreads(ULONG_PTR dwProcessId);

NTSTATUS ProQuery(ULONG_PTR dwProcessId);
NTSTATUS ListUsers();
HRESULT List_Services();
NTSTATUS ListFolder(PCWSTR pszName, ULONG Level);
HRESULT ListTask();
NTSTATUS CreateTask();

NTSTATUS AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)))
	{
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0);

		NtClose(hToken);

	}

	return status;
}

void AdjustPrivileges()
{
	BEGIN_PRIVILEGES(tp, 3)
		LAA(SE_DEBUG_PRIVILEGE),
		LAA(SE_BACKUP_PRIVILEGE),
		LAA(SE_RESTORE_PRIVILEGE),
	END_PRIVILEGES

	if (NTSTATUS status = AdjustPrivileges(&tp))
	{
		DbgPrint("AdjustPrivileges=%x\r\n", status);
	}
}

// cmdline = *cmd[*cmd[*cmd]]
// cmd = name[?opt[?opt]]
// name:
// pro - List all running processes (name + pid)
// id?pid - List threads + loaded modules for a specific pid
// usr - List all uses that are logged into the system
// srv - List all running services and their account owners
// ltsk - List all scheduled tasks
// ntsk - create a new one that runs cmd.exe when a user logs-in.
// fld?path?level - List all files in a specific directory <path> with deep <level>
//
// example:
// *fld?C:\Users\DefaultAppPool?2*ntsk*ltsk*srv*usr*id?b64*pro

void DumpArgs(PWSTR argv[], ULONG argc)
{
	if (argc)
	{
		do 
		{
			DbgPrint("\t%ws\r\n", *argv++);
		} while (--argc);
	}
}

void OnCmd(PWSTR cmd)
{
	PWSTR argv[4]{}, psz;
	ULONG argc = 0;
	PWSTR opt = cmd;

	while (opt = wcschr(opt, '?'))
	{
		if (_countof(argv) == argc)
		{
			DbgPrint("too many params for %hs\r\n\r\n", cmd);
			return;
		}
		*opt++ = 0;
		argv[argc++] = opt;
	}

	ULONG hash;
	UNICODE_STRING str;
	RtlInitUnicodeString(&str, cmd);
	RtlHashUnicodeString(&str, FALSE, HASH_STRING_ALGORITHM_X65599, &hash);
	DbgPrint("case 0x%08x: // \"%ws\"\r\n\tbreak;\r\n", hash, cmd);

	DumpArgs(argv, argc);

	ULONG pid;

	NTSTATUS status = HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);

	switch (hash)
	{
	case 0x3798e4ed: // "pro"
		if (!argc)
		{
			status = List_all_running_processes();
		}
		break;

	case 0x39131377: // "srv"
		if (!argc)
		{
			status = List_Services();
		}
		break;

	case 0xda7233c0: // "ltsk"
		if (!argc)
		{
			status = ListTask();
		}
		break;

	case 0x377fd53e: // "ntsk"
		if (!argc)
		{
			status = CreateTask();
		}
		break;

	case 0x3a1032b4: // "usr"
		if (!argc)
		{
			status = ListUsers();
		}
		break;

	case 0x00691a3b: // "id"
		if (1 == argc)
		{
			if ((pid = wcstoul(argv[0], &psz, 16)) && !*psz)
			{
				0 <= (status = DumpProcessThreads(pid)) &&
					0 <= (status = ProQuery(pid));
			}
			else
			{
				status = HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_1);
			}
		}
		break;

	case 0x32a6485e: // "fld"
		if (2 == argc)
		{
			if ((pid = wcstoul(argv[1], &psz, 16)) < 256 && !*psz)
			{
				status = ListFolder(argv[0], pid);
			}
			else
			{
				status = HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_2);
			}
		}
		break;

	default:
		status = HRESULT_FROM_NT(STATUS_INVALID_INFO_CLASS);
	}

	if (status)
	{
		PrintError(status);
	}
}

void WINAPI ep()
{
	{
		PrintInfo pi;
		InitPrintf();

		AdjustPrivileges();

		PWSTR lpCommandLine = GetCommandLineW();

		PWSTR cmd = 0;

		while (lpCommandLine = wcschr(lpCommandLine, '*'))
		{
			*lpCommandLine++ = 0;

			if (cmd)
			{
				OnCmd(cmd);
			}

			cmd = lpCommandLine;
		}

		if (cmd)
		{
			OnCmd(cmd);
		}
	}

	ExitProcess(0);
}