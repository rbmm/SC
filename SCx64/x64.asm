.code

; void __stdcall ep(struct _PEB *)
extern ?ep@@YAXPEAU_PEB@@@Z : PROC

; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?ep@@YAXPEAU_PEB@@@Z
?epASM@@YAXPEAU_PEB@@@Z endp

include <..\common\nobase64.inc>

include <imp.asm>

end