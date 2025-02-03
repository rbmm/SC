.686

.MODEL FLAT

.code

; void __stdcall OnApc(unsigned long,unsigned long,void *)
extern ?OnApc@@YGXKKPAX@Z : PROC

; void __stdcall epASM()
?epASM@@YGXXZ proc
  jmp ?OnApc@@YGXKKPAX@Z
?epASM@@YGXXZ endp

include <../scentry/nobase.x86.inc>

include <imp.x86.asm>

end