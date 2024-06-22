.code

; int __cdecl Exec(void *,void *,void *)
extern ?Exec@@YAHPEAX00@Z : PROC

; void __cdecl epASM(struct _PEB *)

?epASM@@YAXPEAU_PEB@@@Z proc
  mov rax,gs:[10h]
  xchg rsp,rax    ; set 64-bit stack
  push rax      ; save 32-bit stack
  sub rsp,28h
  
  mov ecx,ecx
  mov edx,edx
  mov r8d,edi
  mov r9d,esi
  
  call ?Exec@@YAHPEAX00@Z

  add rsp,28h
  pop rsp       ; restore 32-bit stack
  ret
?epASM@@YAXPEAU_PEB@@@Z endp

include <nobase64.inc>

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

createFunc ntdll, RtlImageNtHeader
createFunc ntdll, RtlImageDirectoryEntryToData

end