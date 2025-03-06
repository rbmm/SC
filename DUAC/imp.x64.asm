createFunc advapi32, CreateProcessAsUserW

HMOD advapi32, <ADVAPI32.dll>

createFunc kernel32, ExitProcess
createFunc kernel32, LocalFree
createFunc kernel32, OpenProcess
createFunc kernel32, LocalAlloc
createFunc kernel32, WTSGetActiveConsoleSessionId
createFunc kernel32, GetEnvironmentVariableW

HMOD kernel32, <KERNEL32.dll>

createFunc user32, MessageBoxW

HMOD user32, <USER32.dll>

createFunc ntdllp, ZwWriteVirtualMemory
createFunc ntdllp, NtDuplicateObject
createFunc ntdllp, NtSetInformationToken
createFunc ntdllp, RtlFreeHeap
createFunc ntdllp, ZwReadVirtualMemory
createFunc ntdllp, NtOpenProcess
createFunc ntdllp, NtQuerySystemInformation
createFunc ntdllp, NtAdjustPrivilegesToken
createFunc ntdllp, NtDuplicateToken
createFunc ntdllp, NtClose
createFunc ntdllp, ZwQueryInformationThread
createFunc ntdllp, NtSetInformationThread
createFunc ntdllp, NtGetNextThread
createFunc ntdllp, NtOpenProcessToken
createFunc ntdllp, RtlAdjustPrivilege
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, RtlAllocateHeap
createFunc ntdllp, memset

HMOD ntdllp, <>

