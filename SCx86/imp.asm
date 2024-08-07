createFunc  kernel32, GetSystemWindowsDirectoryW, 8
createFunc  kernel32, CreateProcessW, 40
createFunc  kernel32, TerminateProcess, 8
createFunc  kernel32, Wow64RevertWow64FsRedirection, 4
createFunc  kernel32, ExitProcess, 4
createFunc  kernel32, GetSystemWow64DirectoryW, 8
createFunc  kernel32, Wow64DisableWow64FsRedirection, 4

HMOD kernel32, <KERNEL32.dll>

createFunc  WinHttp, WinHttpConnect, 16
createFunc  WinHttp, WinHttpOpenRequest, 28
createFunc  WinHttp, WinHttpSendRequest, 28
createFunc  WinHttp, WinHttpReceiveResponse, 8
createFunc  WinHttp, WinHttpQueryHeaders, 24
createFunc  WinHttp, WinHttpReadData, 16
createFunc  WinHttp, WinHttpCloseHandle, 4
createFunc  WinHttp, WinHttpOpen, 20

HMOD WinHttp, <WINHTTP.dll>

createFunc  ntdllp, NtOpenFile, 24
createFunc  ntdllp, NtQueryDirectoryFile, 44
createFunc  ntdllp, LdrGetProcedureAddress, 16
createFunc  ntdllp, RtlAllocateHeap, 12
createFunc  ntdllp, RtlFreeHeap, 12
createFuncC ntdllp, memcpy
createFunc  ntdllp, LdrLoadDll, 16
createFunc  ntdllp, RtlInitUnicodeString, 8
createFunc  ntdllp, ZwUnmapViewOfSection, 8
createFunc  ntdllp, ZwResumeThread, 8
createFunc  ntdllp, ZwSetContextThread, 8
createFunc  ntdllp, ZwWriteVirtualMemory, 20
createFunc  ntdllp, ZwGetContextThread, 8
createFunc  ntdllp, ZwMapViewOfSection, 40
createFunc  ntdllp, ZwProtectVirtualMemory, 20
createFunc  ntdllp, LdrProcessRelocationBlock, 16
createFunc  ntdllp, RtlImageDirectoryEntryToData, 16
createFunc  ntdllp, RtlImageNtHeader, 4
createFunc  ntdllp, NtQueryInformationProcess, 20
createFunc  ntdllp, RtlImageNtHeaderEx, 20
createFunc  ntdllp, NtClose, 4
createFunc  ntdllp, NtCreateSection, 28
createFuncC ntdllp, wcstoul
createFuncC ntdllp, memset

HMOD ntdllp, <>

