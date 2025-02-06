.686

.MODEL FLAT

sc SEGMENT READ EXECUTE ALIAS(".shlcode") 'CODE'

	ALIGN 16

; long __stdcall LoadLibraryFromMem(void *,unsigned long,void **)
_LoadLibraryFromMem@12 PROC
?LoadLibraryFromMem@@YGJPAXKPAPAX@Z PROC
INCLUDE <../ScLfm/ScLfm.x86.asm>
?LoadLibraryFromMem@@YGJPAXKPAPAX@Z ENDP
_LoadLibraryFromMem@12 ENDP

sc ENDS
end