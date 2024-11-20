.code

; void __cdecl ep(struct _PEB *,unsigned char *,unsigned long)
extern ?ep@@YAXPEAU_PEB@@PEAEK@Z : PROC

; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?ep@@YAXPEAU_PEB@@PEAEK@Z
?epASM@@YAXPEAU_PEB@@@Z endp

include <..\scentry\nobase64.inc>

include <imp.asm>

end