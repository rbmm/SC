.686

.MODEL FLAT

.code

; void __stdcall LoadLibraryFromMem(void *,void *,void *)
extern ?LoadLibraryFromMem@@YGXPAX00@Z : PROC

; void __stdcall epASM(struct _PEB *)
?epASM@@YGXPAU_PEB@@@Z proc
	jmp ?LoadLibraryFromMem@@YGXPAX00@Z
?epASM@@YGXPAU_PEB@@@Z endp

include <../scentry/nobase32.inc>

; const wchar_t *__stdcall getSystem32()
; const wchar_t *__stdcall getDll()

createWstring ?getDll@@YGPB_WXZ, <*.dll>
createWstring ?getSystem32@@YGPB_WXZ, <\system32\\\ >

; const char *__stdcall GetMapViewOfSection()

createAstring ?GetMapViewOfSection@@YGPBDXZ, 'ZwMapViewOfSection'


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

; long __stdcall MyVexHandler(struct _EXCEPTION_POINTERS *)
extern ?MyVexHandler@@YGJPAU_EXCEPTION_POINTERS@@@Z : PROC

; long (__stdcall *__stdcall aMyVexHandler(void))(struct _EXCEPTION_POINTERS *)
?aMyVexHandler@@YGP6GJPAU_EXCEPTION_POINTERS@@@ZXZ proc
	call @@1
	jmp ?MyVexHandler@@YGJPAU_EXCEPTION_POINTERS@@@Z
@@1:
	pop eax
	ret
?aMyVexHandler@@YGP6GJPAU_EXCEPTION_POINTERS@@@ZXZ endp

include <imp86.asm>

end