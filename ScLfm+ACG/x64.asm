.code

; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void *)
extern ?LoadLibraryFromMem@@YAJPEAX_K0@Z : PROC

; void epASM()
?epASM@@YAXXZ proc
	jmp ?LoadLibraryFromMem@@YAJPEAX_K0@Z
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

; long __cdecl retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YAJJ@Z : PROC

; void *__cdecl retFromMapViewOfSectionAddr()
?retFromMapViewOfSectionAddr@@YAPEAXXZ proc
	lea rax,@@1
	ret
@@1:
	mov ecx,eax
	call ?retFromMapViewOfSection@@YAJJ@Z
?retFromMapViewOfSectionAddr@@YAPEAXXZ endp

include <imp.x64.asm>

end