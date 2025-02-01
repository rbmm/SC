createFuncS kernel32, CreateProcessW, 40
createFuncS kernel32, GetSystemWindowsDirectoryW, 8
createFuncS kernel32, TerminateProcess, 8
createFuncS kernel32, Wow64RevertWow64FsRedirection, 4
createFuncS kernel32, ExitProcess, 4
createFuncS kernel32, GetSystemWow64DirectoryW, 8
createFuncS kernel32, Wow64DisableWow64FsRedirection, 4

HMOD kernel32, <KERNEL32.dll>

createFuncS WINHTTP, WinHttpOpenRequest, 28
createFuncS WINHTTP, WinHttpConnect, 16
createFuncS WINHTTP, WinHttpSendRequest, 28
createFuncS WINHTTP, WinHttpReceiveResponse, 8
createFuncS WINHTTP, WinHttpQueryHeaders, 24
createFuncS WINHTTP, WinHttpReadData, 16
createFuncS WINHTTP, WinHttpCloseHandle, 4
createFuncS WINHTTP, WinHttpOpen, 20

HMOD WINHTTP, <WINHTTP.dll>

createFuncS ntdllp, NtCreateSection, 28
createFuncS ntdllp, NtQueryDirectoryFile, 44
createFuncS ntdllp, NtOpenFile, 24
createFuncS ntdllp, RtlInitUnicodeString, 8
createFuncC ntdllp, wcstoul
createFuncS ntdllp, ZwUnmapViewOfSection, 8
createFuncS ntdllp, ZwResumeThread, 8
createFuncS ntdllp, ZwSetContextThread, 8
createFuncS ntdllp, ZwWriteVirtualMemory, 20
createFuncS ntdllp, ZwGetContextThread, 8
createFuncS ntdllp, ZwMapViewOfSection, 40
createFuncS ntdllp, ZwProtectVirtualMemory, 20
createFuncS ntdllp, LdrProcessRelocationBlock, 16
createFuncS ntdllp, RtlImageDirectoryEntryToData, 16
createFuncS ntdllp, RtlImageNtHeader, 4
createFuncS ntdllp, NtQueryInformationProcess, 20
createFuncS ntdllp, RtlImageNtHeaderEx, 20
createFuncS ntdllp, NtClose, 4
createFuncC ntdllp, memcpy
createFuncS ntdllp, LdrLoadDll, 16
createFuncS ntdllp, LdrGetProcedureAddress, 16
createFuncS ntdllp, RtlAllocateHeap, 12
createFuncS ntdllp, RtlFreeHeap, 12
createFuncC ntdllp, memset

HMOD ntdllp, <>

