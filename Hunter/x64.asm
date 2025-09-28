.code
;
 _ERW_ = 1

; void ep()
extern ?ep@@YAXXZ : PROC

; void epASM()
?epASM@@YAXXZ proc

IFNDEF _ERW_
    call protect
ENDIF

    jmp ?ep@@YAXXZ

?epASM@@YAXXZ endp

; __int64 (__cdecl *__cdecl FindEgg(unsigned __int64,void *,unsigned __int64))(void)
?FindEgg@@YAP6A_JXZ_KPEAX0@Z proc
	mov rax,r8
	mov r8,rdi
	xchg rdi,rdx
	repne scasq
	mov rax,rdi
	cmovne rax,rcx
	mov rdi,rdx
	ret
?FindEgg@@YAP6A_JXZ_KPEAX0@Z endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end