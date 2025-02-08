.686

.MODEL FLAT

.code

; void __stdcall ep(struct _PEB *,unsigned char *,unsigned long)
extern ?ep@@YGXPAU_PEB@@PAEK@Z : PROC

; _ERW_ = 1

; void __stdcall epASM()
?epASM@@YGXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?ep@@YGXPAU_PEB@@PAEK@Z
?epASM@@YGXXZ endp

include <../scentry/nobase.x86.inc>

include <imp.x86.asm>

end