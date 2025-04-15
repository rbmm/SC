createFuncS kernel32, LocalFree, 4
createFuncS kernel32, GetStdHandle, 4
createFuncS kernel32, GetConsoleOutputCP, 0
createFuncS kernel32, WriteFile, 20
createFuncS kernel32, WriteConsoleW, 20
createFuncS kernel32, RaiseException, 16
createFuncS kernel32, IsDebuggerPresent, 0
createFuncS kernel32, LocalAlloc, 8
createFuncS kernel32, WideCharToMultiByte, 32
createFuncS kernel32, ExitProcess, 4
createFuncS kernel32, GetCommandLineW, 0
createFuncS kernel32, GetCurrentThreadId, 0

HMOD kernel32, <KERNEL32.dll>

createFuncS user32, EnumThreadWindows, 12

HMOD user32, <USER32.dll>

createFuncS ntdllp, RtlGetFrame, 0
createFuncS ntdllp, RtlPushFrame, 4
createFuncC ntdllp, wcstoul
createFuncC ntdllp, wcschr
createFuncS ntdllp, NtResumeThread, 8
createFuncC ntdllp, _vsnwprintf
createFuncS ntdllp, NtQueryInformationThread, 20
createFuncS ntdllp, NtClose, 4
createFuncS ntdllp, NtGetNextThread, 24
createFuncS ntdllp, NtOpenProcess, 16
createFuncS ntdllp, RtlAdjustPrivilege, 16
createFuncS ntdllp, RtlPopFrame, 4
createFuncS ntdllp, NtQueryVolumeInformationFile, 20
createFuncS ntdllp, NtSuspendThread, 8
createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, LdrGetProcedureAddress, 16

HMOD ntdllp, <>

