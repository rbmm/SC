.code

; void __cdecl ep(struct _PEB *,unsigned char *,unsigned long)
extern ?ep@@YAXPEAU_PEB@@PEAEK@Z : PROC

; void epASM()
?epASM@@YAXXZ proc
  jmp ?ep@@YAXPEAU_PEB@@PEAEK@Z
?epASM@@YAXXZ endp

include <..\scentry\nobase.x64.inc>

include <imp.x64.asm>

end