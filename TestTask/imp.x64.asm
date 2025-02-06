createFunc advapi32, OpenSCManagerW
createFunc advapi32, LsaFreeMemory
createFunc advapi32, OpenServiceW
createFunc advapi32, LsaClose
createFunc advapi32, EnumServicesStatusExW
createFunc advapi32, LsaOpenPolicy
createFunc advapi32, LsaLookupSids
createFunc advapi32, CloseServiceHandle
createFunc advapi32, QueryServiceConfigW

HMOD advapi32, <ADVAPI32.dll>

createFunc kernel32, GetSystemTimeAsFileTime
createFunc kernel32, Sleep
createFunc kernel32, GetCommandLineW
createFunc kernel32, MultiByteToWideChar
createFunc kernel32, GetEnvironmentVariableW
createFunc kernel32, IsDebuggerPresent
createFunc kernel32, GetLastError
createFunc kernel32, GetStdHandle
createFunc kernel32, GetConsoleOutputCP
createFunc kernel32, FormatMessageW
createFunc kernel32, GetModuleHandleW
createFunc kernel32, WriteFile
createFunc kernel32, WriteConsoleW
createFunc kernel32, RaiseException
createFunc kernel32, LocalAlloc
createFunc kernel32, WideCharToMultiByte
createFunc kernel32, LocalFree
createFunc kernel32, ExitProcess

HMOD kernel32, <KERNEL32.dll>

createFunc? Oleaut32, SysFreeString, '#6'
createFunc? Oleaut32, SysAllocString, '#2'

HMOD Oleaut32, <OLEAUT32.dll>

createFunc Secur32, LsaGetLogonSessionData
createFunc Secur32, LsaEnumerateLogonSessions
createFunc Secur32, LsaFreeReturnBuffer

HMOD Secur32, <Secur32.dll>

createFunc ntdllp, RtlGetNtVersionNumbers
createFunc ntdllp, _snwprintf
createFunc ntdllp, RtlSubAuthorityCountSid
createFunc ntdllp, RtlSubAuthoritySid
createFunc ntdllp, RtlIdentifierAuthoritySid
createFunc ntdllp, RtlConvertSidToUnicodeString
createFunc ntdllp, ZwQuerySection
createFunc ntdllp, NtQuerySystemInformation
createFunc ntdllp, RtlImageNtHeader
createFunc ntdllp, RtlImageDirectoryEntryToData
createFunc ntdllp, memset
createFunc ntdllp, sprintf_s
createFunc ntdllp, NtQueryVolumeInformationFile
createFunc ntdllp, _vsnwprintf
createFunc ntdllp, RtlGetFrame
createFunc ntdllp, NtCreateSection
createFunc ntdllp, NtOpenProcess
createFunc ntdllp, ZwUnmapViewOfSection
createFunc ntdllp, ZwMapViewOfSection
createFunc ntdllp, ZwTerminateThread
createFunc ntdllp, ZwWaitForSingleObject
createFunc ntdllp, RtlCopySid
createFunc ntdllp, NtSetInformationThread
createFunc ntdllp, RtlCreateUserThread
createFunc ntdllp, ZwQueueApcThread
createFunc ntdllp, RtlQueueApcWow64Thread
createFunc ntdllp, RtlFreeUnicodeString
createFunc ntdllp, RtlDosPathNameToNtPathName_U_WithStatus
createFunc ntdllp, NtQueryDirectoryFile
createFunc ntdllp, NtOpenFile
createFunc ntdllp, wcstoul
createFunc ntdllp, RtlHashUnicodeString
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, wcschr
createFunc ntdllp, NtClose
createFunc ntdllp, NtAdjustPrivilegesToken
createFunc ntdllp, NtOpenProcessToken
createFunc ntdllp, RtlPopFrame
createFunc ntdllp, RtlPushFrame
createFunc ntdllp, NtQueryVirtualMemory
createFunc ntdllp, RtlFreeHeap
createFunc ntdllp, RtlAllocateHeap
createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, RtlLengthSid
createFunc ntdllp, RtlEqualSid
createFunc ntdllp, ZwResumeThread
createFunc ntdllp, NtQueryInformationToken
createFunc ntdllp, NtQueryInformationProcess
createFunc ntdllp, ZwOpenSection
createFunc ntdllp, NtSetInformationVirtualMemory

HMOD ntdllp, <>

createFunc ole32, CoCreateInstance
createFunc ole32, CoInitializeEx
createFunc ole32, CoUninitialize

HMOD ole32, <ole32.dll>

