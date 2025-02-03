.686

.MODEL FLAT

.code

; long __stdcall LoadLibraryFromMem(void *,unsigned long,void **)
extern ?LoadLibraryFromMem@@YGJPAXKPAPAX@Z : PROC

; void __stdcall epASM()
?epASM@@YGXXZ proc
	jmp ?LoadLibraryFromMem@@YGJPAXKPAPAX@Z
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

end