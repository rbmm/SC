
.code

; long __cdecl retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YAJJ@Z : PROC

; long __cdecl aretFromMapViewOfSection(void)
?aretFromMapViewOfSection@@YAJXZ proc
	mov ecx,eax
	call ?retFromMapViewOfSection@@YAJJ@Z
?aretFromMapViewOfSection@@YAJXZ endp

END