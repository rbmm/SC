createFunc kernel32, LocalFree
createFunc kernel32, GetStdHandle
createFunc kernel32, GetConsoleOutputCP
createFunc kernel32, WriteFile
createFunc kernel32, WriteConsoleW
createFunc kernel32, RaiseException
createFunc kernel32, IsDebuggerPresent
createFunc kernel32, LocalAlloc
createFunc kernel32, WideCharToMultiByte
createFunc kernel32, ExitProcess
createFunc kernel32, GetCommandLineW
createFunc kernel32, GetCurrentThreadId

HMOD kernel32, <KERNEL32.dll>

createFunc user32, EnumThreadWindows

HMOD user32, <USER32.dll>

createFunc ntdllp, RtlGetFrame
createFunc ntdllp, RtlPushFrame
createFunc ntdllp, wcstoul
createFunc ntdllp, wcschr
createFunc ntdllp, NtResumeThread
createFunc ntdllp, _vsnwprintf
createFunc ntdllp, NtQueryInformationThread
createFunc ntdllp, NtClose
createFunc ntdllp, NtGetNextThread
createFunc ntdllp, NtOpenProcess
createFunc ntdllp, RtlAdjustPrivilege
createFunc ntdllp, RtlPopFrame
createFunc ntdllp, NtQueryVolumeInformationFile
createFunc ntdllp, NtSuspendThread
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrGetProcedureAddress

HMOD ntdllp, <>

