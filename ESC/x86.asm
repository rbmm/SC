.686

.MODEL FLAT
.code

ep proc
	mov eax,[esp]
	mov edx,[esp + 4]
	sub esp,8
	mov [esp],eax
	mov [esp + 4],edx
	lea ecx,code_end
	call ?addr
	mov [esp+12],eax
	lea ecx,code_begin
	call ?addr
	sub [esp + 12],eax
	mov [esp + 8],eax
	ALIGN 16
INCLUDE <../DecryptUnpackRun/DecryptUnpackRun.x86.asm>
ep endp

?addr proc private
	call @@0
@@0:
	pop eax
	lea edx,?addr
	sub ecx,edx
	lea eax,[ecx + eax - 5]
	ret
?addr endp

.const

code_begin LABEL BYTE
INCLUDE <../hello/hello.x86.asm>
code_end LABEL BYTE

end