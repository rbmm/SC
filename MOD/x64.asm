.code

; void __cdecl OnApc(unsigned long,unsigned long,void *)
extern ?OnApc@@YAXKKPEAX@Z : PROC

; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?OnApc@@YAXKKPEAX@Z
?epASM@@YAXPEAU_PEB@@@Z endp

include <..\scentry\nobase64.inc>

include <imp.asm>

end