createFunc  KERNEL32, GetSystemWindowsDirectoryW, 8
createFunc  KERNEL32, CreateProcessW, 40
createFunc  KERNEL32, TerminateProcess, 8
createFunc  KERNEL32, Wow64RevertWow64FsRedirection, 4
createFunc  KERNEL32, ExitProcess, 4
createFunc  KERNEL32, GetSystemWow64DirectoryW, 8
createFunc  KERNEL32, Wow64DisableWow64FsRedirection, 4

HMOD KERNEL32, <KERNEL32.dll>

createFunc  WINHTTP, WinHttpConnect, 16
createFunc  WINHTTP, WinHttpOpenRequest, 28
createFunc  WINHTTP, WinHttpSendRequest, 28
createFunc  WINHTTP, WinHttpReceiveResponse, 8
createFunc  WINHTTP, WinHttpQueryHeaders, 24
createFunc  WINHTTP, WinHttpReadData, 16
createFunc  WINHTTP, WinHttpCloseHandle, 4
createFunc  WINHTTP, WinHttpOpen, 20

HMOD WINHTTP, <WINHTTP.dll>

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

