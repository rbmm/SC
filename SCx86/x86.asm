.686

.MODEL FLAT

.code

; void __stdcall ep(struct _PEB *)
extern ?ep@@YGXPAU_PEB@@@Z : PROC

; void __stdcall epASM(struct _PEB *)
?epASM@@YGXPAU_PEB@@@Z proc
	jmp ?ep@@YGXPAU_PEB@@@Z
?epASM@@YGXPAU_PEB@@@Z endp

include <nobase32.inc>

; const char *__stdcall host(void)

createWstring ?host@@YGPB_WXZ, <the.earth.li>
createWstring ?URL32@@YGPB_WXZ, </~sgtatham/putty/latest/w32/putty.exe>
createWstring ?URL64@@YGPB_WXZ, </~sgtatham/putty/latest/w64/putty.exe>

createWstring ?DLLMask@@YGPB_WXZ, <*.dll>
createWstring ?System32@@YGPB_WXZ, <\systemroot\system32\\\ >
createWstring ?Syswow64@@YGPB_WXZ, <\systemroot\syswow64\\\ >
createWstring ?explorer@@YGPB_WXZ, <\explorer.exe>

; int __fastcall Exec64(void *,void *,void *)
?Exec64@@YIHPAX00@Z proc
  xchg edi,[esp+4]
  xchg esi,[esp+8]
  xchg ebp,[esp+12]
  jmp @2
  ALIGN 16
@3:
INCLUDE <../ExecX64/ExecX64.asm>
@2:
  push 33h
  call @1
  ;++++++++ x64 +++++++++
  call @3
  retf
  ;-------- x64 ---------
@1:
  call fword ptr [esp]
  pop ecx
  pop ecx
  mov edi,[esp+4]
  mov esi,[esp+8]
  mov ebp,[esp+12]
  ret 12
?Exec64@@YIHPAX00@Z endp

HMOD kernel32
HMOD WinHttp

createFuncC ntdll, DbgPrint
createFuncC ntdll, wcstoul
createFuncC ntdll, memset
createFuncC ntdll, memcpy

createFunc ntdll, LdrGetProcedureAddress, 16
createFunc ntdll, LdrLoadDll, 16
createFunc ntdll, LdrUnloadDll, 4
createFunc ntdll, LdrGetDllHandle, 16
createFunc ntdll, LdrProcessRelocationBlock, 16

createFunc ntdll, NtCreateSection, 28
createFunc ntdll, ZwMapViewOfSection, 40
createFunc ntdll, ZwUnmapViewOfSection, 8
createFunc ntdll, ZwProtectVirtualMemory, 20
createFunc ntdll, ZwWriteVirtualMemory,20

createFunc ntdll, NtOpenFile, 24
createFunc ntdll, NtQueryDirectoryFile, 44
createFunc ntdll, NtClose, 4
createFunc ntdll, NtReadFile, 36
createFunc ntdll, NtWriteFile, 36

createFunc ntdll, RtlInitAnsiString, 8
createFunc ntdll, RtlInitUnicodeString, 8
createFunc ntdll, RtlEqualUnicodeString, 12
createFunc ntdll, RtlAppendUnicodeStringToString, 8
createFunc ntdll, RtlAppendUnicodeToString, 8
createFunc ntdll, RtlGetNtSystemRoot, 0
createFunc ntdll, RtlDosPathNameToNtPathName_U_WithStatus, 16
createFunc ntdll, RtlFreeUnicodeString, 4

createFunc ntdll, RtlAllocateHeap, 12
createFunc ntdll, RtlFreeHeap, 12

createFunc ntdll, RtlImageNtHeaderEx, 20
createFunc ntdll, RtlImageDirectoryEntryToData, 16

createFunc ntdll, NtQueryInformationProcess,20
createFunc ntdll, RtlImageNtHeader,4
createFunc ntdll, ZwGetContextThread,8
createFunc ntdll, ZwSetContextThread,8
createFunc ntdll, ZwResumeThread,8
createFunc ntdll, ZwQueryInformationThread,20
createFunc ntdll, ZwSetInformationThread,16


createFunc kernel32, ExitProcess, 4
createFunc kernel32, GetSystemWindowsDirectoryW, 8
createFunc kernel32, GetSystemWow64DirectoryW, 8
createFunc kernel32, TerminateProcess, 8
createFunc kernel32, Wow64DisableWow64FsRedirection, 4
createFunc kernel32, Wow64RevertWow64FsRedirection, 4
createFunc kernel32, CreateProcessW, 40

createFunc WinHttp, WinHttpCloseHandle, 4
createFunc WinHttp, WinHttpOpen, 20
createFunc WinHttp, WinHttpConnect, 16
createFunc WinHttp, WinHttpOpenRequest, 28
createFunc WinHttp, WinHttpSendRequest, 28
createFunc WinHttp, WinHttpQueryHeaders, 24
createFunc WinHttp, WinHttpReceiveResponse, 8
createFunc WinHttp, WinHttpReadData, 16


end