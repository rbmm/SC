.code

; void __cdecl ep(struct _PEB *,unsigned char *,unsigned long)
extern ?ep@@YAXPEAU_PEB@@PEAEK@Z : PROC

; _ERW_ = 1

; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?ep@@YAXPEAU_PEB@@PEAEK@Z
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end