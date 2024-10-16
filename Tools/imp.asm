createFunc  advapi32, OpenSCManagerW
createFunc  advapi32, LsaFreeMemory
createFunc  advapi32, OpenServiceW
createFunc  advapi32, LsaClose
createFunc  advapi32, EnumServicesStatusExW
createFunc  advapi32, LsaOpenPolicy
createFunc  advapi32, LsaLookupSids
createFunc  advapi32, CloseServiceHandle
createFunc  advapi32, QueryServiceConfigW

HMOD advapi32, <ADVAPI32.dll>

createFunc  kernel32, GetSystemTimeAsFileTime
createFunc  kernel32, ExitProcess
createFunc  kernel32, LocalFree
createFunc  kernel32, MultiByteToWideChar
createFunc  kernel32, GetEnvironmentVariableW
createFunc  kernel32, GetCommandLineW
createFunc  kernel32, GetLastError
createFunc  kernel32, GetStdHandle
createFunc  kernel32, GetConsoleOutputCP
createFunc  kernel32, FormatMessageW
createFunc  kernel32, GetModuleHandleW
createFunc  kernel32, WriteFile
createFunc  kernel32, WriteConsoleW
createFunc  kernel32, RaiseException
createFunc  kernel32, IsDebuggerPresent
createFunc  kernel32, LocalAlloc
createFunc  kernel32, WideCharToMultiByte

HMOD kernel32, <KERNEL32.dll>

createFunc  Oleaut32, SysFreeString
createFunc  Oleaut32, SysAllocString

HMOD Oleaut32, <OLEAUT32.dll>

createFunc  Secur32, LsaGetLogonSessionData
createFunc  Secur32, LsaEnumerateLogonSessions
createFunc  Secur32, LsaFreeReturnBuffer

HMOD Secur32, <Secur32.dll>

createFunc  ntdllp, RtlEqualSid
createFunc  ntdllp, RtlLengthSid
createFunc  ntdllp, RtlCopySid
createFunc  ntdllp, RtlGetNtVersionNumbers
createFunc  ntdllp, _snwprintf
createFunc  ntdllp, RtlSubAuthorityCountSid
createFunc  ntdllp, RtlSubAuthoritySid
createFunc  ntdllp, RtlIdentifierAuthoritySid
createFunc  ntdllp, _vsnwprintf
createFunc  ntdllp, __chkstk
createFunc  ntdllp, ZwQuerySection
createFunc  ntdllp, ZwOpenSection
createFunc  ntdllp, RtlImageNtHeader
createFunc  ntdllp, RtlImageDirectoryEntryToData
createFunc  ntdllp, RtlGetFrame
createFunc  ntdllp, NtCreateSection
createFunc  ntdllp, NtOpenProcess
createFunc  ntdllp, ZwUnmapViewOfSection
createFunc  ntdllp, ZwMapViewOfSection
createFunc  ntdllp, ZwTerminateThread
createFunc  ntdllp, ZwWaitForSingleObject
createFunc  ntdllp, ZwResumeThread
createFunc  ntdllp, NtQueryInformationToken
createFunc  ntdllp, RtlCreateUserThread
createFunc  ntdllp, ZwQueueApcThread
createFunc  ntdllp, RtlExitUserThread
createFunc  ntdllp, LdrQueryProcessModuleInformation
createFunc  ntdllp, RtlQueueApcWow64Thread
createFunc  ntdllp, RtlFreeUnicodeString
createFunc  ntdllp, RtlDosPathNameToNtPathName_U_WithStatus
createFunc  ntdllp, NtQueryDirectoryFile
createFunc  ntdllp, NtOpenFile
createFunc  ntdllp, wcstoul
createFunc  ntdllp, RtlHashUnicodeString
createFunc  ntdllp, RtlInitUnicodeString
createFunc  ntdllp, wcschr
createFunc  ntdllp, NtClose
createFunc  ntdllp, NtAdjustPrivilegesToken
createFunc  ntdllp, NtOpenProcessToken
createFunc  ntdllp, RtlPopFrame
createFunc  ntdllp, RtlPushFrame
createFunc  ntdllp, NtQueryVirtualMemory
createFunc  ntdllp, RtlFreeHeap
createFunc  ntdllp, RtlAllocateHeap
createFunc  ntdllp, LdrGetProcedureAddress
createFunc  ntdllp, LdrLoadDll
createFunc  ntdllp, NtQuerySystemInformation
createFunc  ntdllp, sprintf_s
createFunc  ntdllp, NtSetInformationThread
createFunc  ntdllp, NtQueryVolumeInformationFile
createFunc  ntdllp, NtQueryInformationProcess
createFunc  ntdllp, RtlConvertSidToUnicodeString
createFunc  ntdllp, NtSetInformationVirtualMemory
createFunc  ntdllp, memset

HMOD ntdllp, <>

createFunc  ole32, CoInitializeEx
createFunc  ole32, CoCreateInstance
createFunc  ole32, CoUninitialize

HMOD ole32, <ole32.dll>

