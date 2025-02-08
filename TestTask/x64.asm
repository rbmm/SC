.code

; void ep()
extern ?ep@@YAXXZ : PROC

;_ERW_ = 1
 
; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?ep@@YAXXZ
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

public ?xml_begin@@3QBDB, ?xml_end@@3QBDB

_TEXT$cpp$r SEGMENT

?xml_begin@@3QBDB LABEL BYTE
include <tsk.asm>
?xml_end@@3QBDB LABEL BYTE

_TEXT$cpp$r ends
end