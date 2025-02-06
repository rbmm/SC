.code

; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void **)
extern ?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z : PROC

; void epASM()
?epASM@@YAXXZ proc
  call protect
  jmp ?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z
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