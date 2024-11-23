
.code

ep proc
	lea rdx,code_begin
	lea r8,code_end
	sub r8,rdx
INCLUDE <../DecryptUnpackRun/DecryptUnpackRun.asm>
ep endp

.const

code_begin:
INCLUDE <../CertLogon/cl.asm>
code_end:

end