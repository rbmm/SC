.686

.MODEL FLAT

.code

; _ERW_ = 1

; void __fastcall ep(void *,unsigned long)
extern ?ep@@YIXPAXK@Z : PROC

; void __stdcall epASM()
?epASM@@YGXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

	lea ecx,code_end
	call ?__Address@@YIPAXPBX@Z
	push eax
	lea ecx,code_begin
	call ?__Address@@YIPAXPBX@Z
	pop edx
	sub edx,eax
	mov ecx,eax

    jmp ?ep@@YIXPAXK@Z
?epASM@@YGXXZ endp


include <../scentry/nobase.x86.inc>

; long __fastcall retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YIJJ@Z : PROC

; long __stdcall aretFromMapViewOfSection(void)
?aretFromMapViewOfSection@@YGJXZ proc
  mov ecx,eax
  call ?retFromMapViewOfSection@@YIJJ@Z
?aretFromMapViewOfSection@@YGJXZ endp


include <imp.x86.asm>

code_begin LABEL BYTE
INCLUDE <../dll/x86.asm>
code_end LABEL BYTE

end