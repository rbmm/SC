.code

; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void *)
extern ?LoadLibraryFromMem@@YAJPEAX_K0@Z : PROC

; _ERW_ = 1

; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

  jmp ?LoadLibraryFromMem@@YAJPEAX_K0@Z
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

end