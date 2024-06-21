createAstring macro name, string
name proc
  call @@1
  DB string,0
@@1:
  pop eax
  ret
name endp
endm

WSTRING macro text
  FORC arg, text
  DW '&arg'
  ENDM
  DW 0
endm

createWstring macro name, string
  ALIGN 2
  nop
name proc
  call @@1
  WSTRING string
@@1:
  pop eax
  ret
name endp
endm

_HMOD macro name, str
  ALIGN 4
  nop
  nop
  nop
name proc private
  call @@1
  DD 0
  WSTRING str
@@1:
  pop ecx

  ret
name endp
endm

HMOD macro name
_HMOD name, name
endm

_createFunc2 macro hmod, name, string
  ALIGN 4
  nop
  nop
name proc
  call hmod
  call @@1
  DD 0
  DB string,0
@@1: 
  pop edx
  jmp common_imp_call
name endp
endm

createFunc macro hmod, name, n
_createFunc2 hmod, @CatStr(_,name,@,n), '&name'
endm

createFuncC macro hmod, name
_createFunc2 hmod, @CatStr(_,name), '&name'
endm


; void *__fastcall NT::get_hmod(const wchar_t *)
extern ?get_hmod@NT@@YIPAXPB_W@Z : PROC

; void *__fastcall NT::GetFuncAddressEx(struct _IMAGE_DOS_HEADER *,const char *)
extern ?GetFuncAddressEx@NT@@YIPAXPAU_IMAGE_DOS_HEADER@@PBD@Z : PROC

; ecx -> mod, edx -> func
common_imp_call proc private
  mov eax,[edx]
  test eax,eax
  jnz @@1
  push edx
  mov eax,[ecx]; *phmod
  test eax,eax
  jnz @@2
  push ecx
  lea ecx,[ecx + 4]
  call ?get_hmod@NT@@YIPAXPB_W@Z
  pop ecx
  mov [ecx],eax
  mov edx,[esp]
@@2:
  lea edx,[edx + 4]
  mov ecx,eax
  call ?GetFuncAddressEx@NT@@YIPAXPAU_IMAGE_DOS_HEADER@@PBD@Z
  pop edx
  mov [edx],eax
@@1:
  jmp eax
common_imp_call endp

_HMOD ntdll,<>




