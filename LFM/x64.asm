.code

; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void **)
extern ?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z : PROC


; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z
?epASM@@YAXPEAU_PEB@@@Z endp

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

; long __cdecl MyVexHandler(struct _EXCEPTION_POINTERS *)
extern ?MyVexHandler@@YAJPEAU_EXCEPTION_POINTERS@@@Z : PROC

; long (__cdecl *__cdecl aMyVexHandler(void))(struct _EXCEPTION_POINTERS *)
?aMyVexHandler@@YAP6AJPEAU_EXCEPTION_POINTERS@@@ZXZ proc
	lea rax,@@1
	ret
@@1:
	jmp ?MyVexHandler@@YAJPEAU_EXCEPTION_POINTERS@@@Z
?aMyVexHandler@@YAP6AJPEAU_EXCEPTION_POINTERS@@@ZXZ endp

include <..\scentry\nobase64.inc>

include <imp.asm>

end