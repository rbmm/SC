.code

; _ERW_ = 1

; void __cdecl ep(void *,unsigned long)
extern ?ep@@YAXPEAXK@Z : PROC

; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

	lea rcx,code_begin
	lea rdx,code_end
	sub rdx,rcx
    jmp ?ep@@YAXPEAXK@Z

?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

; long __cdecl retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YAJJ@Z : PROC

; long __cdecl aretFromMapViewOfSection(void)
?aretFromMapViewOfSection@@YAJXZ proc
  mov ecx,eax
  call ?retFromMapViewOfSection@@YAJJ@Z
?aretFromMapViewOfSection@@YAJXZ endp

include <imp.x64.asm>

code_begin LABEL BYTE
INCLUDE <../dll/x64.asm>
code_end LABEL BYTE

end