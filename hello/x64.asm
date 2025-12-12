.code

; _ERW_ = 1

; void ep()
extern ?ep@@YAXXZ : PROC

; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?ep@@YAXXZ
;  DD IMAGEREL @imp_begin@
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end