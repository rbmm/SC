.code
;
_ERW_ = 1

; void __cdecl epApc(unsigned long,void *,void *)
extern ?epApc@@YAXKPEAX_K@Z : PROC


; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

    jmp ?epApc@@YAXKPEAX_K@Z

?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end