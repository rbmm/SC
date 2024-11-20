.code

; void __cdecl OnApc(unsigned long,unsigned long,void *)
extern ?OnApc@@YAXKKPEAX@Z : PROC

; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?OnApc@@YAXKKPEAX@Z
?epASM@@YAXPEAU_PEB@@@Z endp

; long __cdecl MySeciAllocateAndSetCallFlags(unsigned long,int *)
extern ?MySeciAllocateAndSetCallFlags@@YAJKPEAH@Z : PROC

; void *__cdecl MySeciAllocateAndSetCallFlagsAddr()
?MySeciAllocateAndSetCallFlagsAddr@@YAPEAXXZ proc
	lea rax,?MySeciAllocateAndSetCallFlags@@YAJKPEAH@Z
	ret
?MySeciAllocateAndSetCallFlagsAddr@@YAPEAXXZ endp

include <..\scentry\nobase64.inc>

include <imp.asm>

end