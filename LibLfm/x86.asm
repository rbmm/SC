.686
.model flat

.code
; long __fastcall retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YIJJ@Z : PROC

; long __stdcall aretFromMapViewOfSection(void)
?aretFromMapViewOfSection@@YGJXZ proc
	mov ecx,eax
	call ?retFromMapViewOfSection@@YIJJ@Z
?aretFromMapViewOfSection@@YGJXZ endp

end
