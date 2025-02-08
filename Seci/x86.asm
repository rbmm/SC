.686

.MODEL FLAT

.code

; void __stdcall OnApc(unsigned long,unsigned long,void *)
extern ?OnApc@@YGXKKPAX@Z : PROC

; _ERW_ = 1

; void __stdcall epASM()
?epASM@@YGXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?OnApc@@YGXKKPAX@Z
?epASM@@YGXXZ endp

include <../scentry/nobase.x86.inc>

include <imp.x86.asm>

end