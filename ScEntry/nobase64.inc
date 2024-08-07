createAstring macro name, string
name proc
	lea rax,@@1
	ret
@@1:
	DB string,0
name endp
endm

WSTRING macro text
	FORC arg, text
	DW '&arg'
	ENDM
	DW 0
endm

createWstring macro name, string
name proc
	lea rax,@@1
	ret
	ALIGN 2
@@1:
	WSTRING string
name endp
endm

HMOD macro name, str
name proc private
	lea r11,@@1
	ret
	ALIGN 8
@@1:
	DQ 0
	WSTRING str
name endp
endm

_createFunc2 macro hmod, name, string
name proc
	call hmod
	lea r10,@@1
	jmp common_imp_call
	ALIGN 8
@@1: 
	DQ 0
	DB string,0
name endp
endm

createFunc macro hmod, name
_createFunc2 hmod, name, '&name'
endm

extern ?get_hmod@@YAPEAXPEB_W@Z : PROC ; void *__cdecl get_hmod(const wchar_t *)
extern ?GetFuncAddressEx@@YAPEAXPEAU_IMAGE_DOS_HEADER@@PEBD@Z : PROC ; void *__cdecl GetFuncAddressEx(struct _IMAGE_DOS_HEADER *,const char *)

common_imp_call proc private
  mov rax,[r10]
  test rax,rax
  jnz @@1
  push r9
  push r8
  push rdx
  push rcx
  push r10
  push r11
  sub rsp,28h
  mov rax,[r11]; *phmod
  test rax,rax
  jnz @@2
  lea rcx,[r11 + 8]
  call ?get_hmod@@YAPEAXPEB_W@Z
  mov r11,[rsp + 28h]
  mov r10,[rsp + 30h]
  mov [r11],rax
@@2:
  lea rdx,[r10 + 8]
  mov rcx,rax
  call ?GetFuncAddressEx@@YAPEAXPEAU_IMAGE_DOS_HEADER@@PEBD@Z
  add rsp,28h
  pop r11
  pop r10
  pop rcx
  pop rdx
  pop r8
  pop r9
  mov [r10],rax
@@1:
  jmp rax
common_imp_call endp