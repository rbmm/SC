.code

; void __cdecl OnApc(unsigned long,unsigned long,void *)
extern ?OnApc@@YAXKKPEAX@Z : PROC

; void epASM()
?epASM@@YAXXZ proc
	jmp ?OnApc@@YAXKKPEAX@Z
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end