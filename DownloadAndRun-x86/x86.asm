.686

.MODEL FLAT

.code

; void __stdcall ep()
extern ?ep@@YGXXZ : PROC

; void __stdcall epASM()
?epASM@@YGXXZ proc
  call protect
  jmp ?ep@@YGXXZ
?epASM@@YGXXZ endp

include <../scentry/nobase.x86.inc>

include <imp.x86.asm>

; int __fastcall Exec64(void *,void *,void *)
?Exec64@@YIHPAX00@Z proc
  xchg edi,[esp+4]
  xchg esi,[esp+8]
  xchg ebp,[esp+12]
  push 33h
  call @1
  ;++++++++ x64 +++++++++
  call x64sc
  retf
  ;-------- x64 ---------
@1:
  call fword ptr [esp]
  pop ecx
  pop ecx
  mov edi,[esp+4]
  mov esi,[esp+8]
  mov ebp,[esp+12]
  ret 4
?Exec64@@YIHPAX00@Z endp

_TEXT$cpp$t SEGMENT ALIGN(4096) 'CODE'

x64sc proc private
INCLUDE <../Exec-X64/Exec-x64.x64.asm>
x64sc endp

_TEXT$cpp$t ENDS

end