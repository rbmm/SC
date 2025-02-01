
.code

ep proc
	lea rdx,code_begin
	lea r8,code_end
	sub r8,rdx
	ALIGN 16
INCLUDE <../DecryptUnpackRun/DecryptUnpackRun.x64.asm>
ep endp

.const

code_begin LABEL BYTE
INCLUDE <../hello/hello.x64.asm>
code_end LABEL BYTE

end