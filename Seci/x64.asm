.code

; void __cdecl OnApc(unsigned long,unsigned long,void *)
extern ?OnApc@@YAXKKPEAX@Z : PROC

; _ERW_ = 1

; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?OnApc@@YAXKKPEAX@Z
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end