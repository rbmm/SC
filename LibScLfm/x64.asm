shellcode SEGMENT READ EXECUTE ALIAS(".shlcode") 'CODE'

	ALIGN 16
; long __cdecl LoadLibraryFromMem(void *,unsigned __int64,void **)

?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z PROC
LoadLibraryFromMem PROC
INCLUDE <../ScLfm/ScLfm.x64.asm>
LoadLibraryFromMem ENDP
?LoadLibraryFromMem@@YAJPEAX_KPEAPEAX@Z ENDP

shellcode ENDS

end