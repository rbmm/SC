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

include <imp.asm>

end