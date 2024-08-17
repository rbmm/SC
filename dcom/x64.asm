; unsigned short __cdecl CImport::DirectoryEntry(void)
extern ?DirectoryEntry@CImport@@UEAAGXZ : PROC
; unsigned long __cdecl CImport::Name(unsigned long)
extern ?Name@CImport@@UEAAKK@Z : PROC
; unsigned long __cdecl CImport::Next(void)
extern ?Next@CImport@@UEAAKXZ : PROC
; unsigned long __cdecl CImport::rvaINT(void)
extern ?rvaINT@CImport@@UEAAKXZ : PROC
; unsigned long __cdecl CImport::rvaIAT(void)
extern ?rvaIAT@CImport@@UEAAKXZ : PROC


; unsigned short __cdecl CDImport::DirectoryEntry(void)
extern ?DirectoryEntry@CDImport@@UEAAGXZ : PROC
; unsigned long __cdecl CDImport::Name(unsigned long)
extern ?Name@CDImport@@UEAAKK@Z : PROC
; unsigned long __cdecl CDImport::Next(void)
extern ?Next@CDImport@@UEAAKXZ : PROC
; unsigned long __cdecl CDImport::rvaINT(void)
extern ?rvaINT@CDImport@@UEAAKXZ : PROC
; unsigned long __cdecl CDImport::rvaIAT(void)
extern ?rvaIAT@CDImport@@UEAAKXZ : PROC

AddEntry MACRO fn
	lea rax,fn
	mov [rcx],rax
	add rcx,r8
ENDM

.code

; void __cdecl ep(unsigned long,void *,void *)
extern ?ep@@YAXKPEAX0@Z : PROC

; void __cdecl epASM(struct _PEB *)
?epASM@@YAXPEAU_PEB@@@Z proc
	jmp ?ep@@YAXKPEAX0@Z
?epASM@@YAXPEAU_PEB@@@Z endp

	ALIGN 8
_G_Token LABEL QWORD
	DQ 0

; void *__cdecl GetToken(void)
?GetToken@@YAPEAXXZ proc
	mov rax,_G_Token
	ret
?GetToken@@YAPEAXXZ endp

; void __cdecl SetToken(void *)
?SetToken@@YAXPEAX@Z proc
	mov _G_Token,rcx
	ret
?SetToken@@YAXPEAX@Z endp

; struct CImport *__cdecl InitVT(void **,struct CImport *)
?InitVT@@YAPEAUCImport@@PEAPEAXPEAU1@@Z proc
	mov [rdx],rcx
	mov r8,8
	AddEntry ?DirectoryEntry@CImport@@UEAAGXZ
	AddEntry ?Name@CImport@@UEAAKK@Z
	AddEntry ?Next@CImport@@UEAAKXZ
	AddEntry ?rvaINT@CImport@@UEAAKXZ
	AddEntry ?rvaIAT@CImport@@UEAAKXZ
	mov rax,rdx
	ret
?InitVT@@YAPEAUCImport@@PEAPEAXPEAU1@@Z endp

; struct CDImport *__cdecl InitVT(void **,struct CDImport *)
?InitVT@@YAPEAUCDImport@@PEAPEAXPEAU1@@Z proc
	mov [rdx],rcx
	mov r8,8
	AddEntry ?DirectoryEntry@CDImport@@UEAAGXZ
	AddEntry ?Name@CDImport@@UEAAKK@Z
	AddEntry ?Next@CDImport@@UEAAKXZ
	AddEntry ?rvaINT@CDImport@@UEAAKXZ
	AddEntry ?rvaIAT@CDImport@@UEAAKXZ
	mov rax,rdx
	ret
?InitVT@@YAPEAUCDImport@@PEAPEAXPEAU1@@Z endp


include <..\ScEntry\nobase64.inc>

include <imp.asm>

end