.code

; void __stdcall ep(struct _PEB *)
extern ?ep@@YAXPEAU_PEB@@@Z : PROC

; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?ep@@YAXPEAU_PEB@@@Z
?epASM@@YAXPEAU_PEB@@@Z endp

include <..\scentry\nobase64.inc>

include <imp.asm>

public ?xml_begin@@3QBDB, ?xml_end@@3QBDB

_TEXT$dat SEGMENT

?xml_begin@@3QBDB:
include <tsk.asm>
?xml_end@@3QBDB:

_TEXT$dat ends

end