.686

.MODEL FLAT

.code

; long __stdcall LoadLibraryFromMem(void *,unsigned long,void *)
extern ?LoadLibraryFromMem@@YGJPAXK0@Z : PROC

; void __stdcall epASM()
?epASM@@YGXXZ proc
	jmp ?LoadLibraryFromMem@@YGJPAXK0@Z
?epASM@@YGXXZ endp

include <../scentry/nobase.x86.inc>

; long __fastcall retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YIJJ@Z : PROC

; void *__stdcall retFromMapViewOfSectionAddr(void)
?retFromMapViewOfSectionAddr@@YGPAXXZ proc
	call @@1
	mov ecx,eax
	call ?retFromMapViewOfSection@@YIJJ@Z
@@1:
	pop eax
	ret
?retFromMapViewOfSectionAddr@@YGPAXXZ endp

include <imp.x86.asm>

end