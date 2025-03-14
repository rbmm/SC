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

IFDEF _ERW_
	_ALIGN_ = 16
ELSE
	_ALIGN_ = 4096
ENDIF

HMOD macro name, str

_TEXT$cpp$u SEGMENT ALIGN(_ALIGN_)
	ALIGN 4
@CatStr(@,name) LABEL BYTE
	DD 0
	WSTRING str
_TEXT$cpp$u ENDS

.code

endm

; hmod   : hmod for dll
; name   : decorated name of the function (as in lib file )
; string : name from dll export table or #ordinal ( #123 )

createFunc? macro hmod, name, string
_TEXT$cpp$u SEGMENT ALIGN(_ALIGN_)
	ALIGN 4
@CatStr(?,name) LABEL BYTE
	DD 0
	DB string,0
_TEXT$cpp$u ENDS

.code

name proc
  push ecx
  push edx
  lea ecx,@CatStr(@,hmod)
  call ?__Address@@YIPAXPBX@Z
  push eax
  lea ecx,@CatStr(?,name)
  call ?__Address@@YIPAXPBX@Z
  mov edx,eax
  pop ecx
  jmp common_imp_call
name endp

endm

; name = _string@n , __stdcall api
createFuncS macro hmod, string, n
createFunc? hmod, @CatStr(_,string,@,n), '&string'
endm

; name = @string@n , __fastcall api
createFuncF macro hmod, string, n
createFunc? hmod, @CatStr(@,string,@,n), '&string'
endm

; name = _string , __cdecl api
createFuncC macro hmod, string
createFunc? hmod, @CatStr(_,string), '&string'
endm

; name == string
createFunc macro hmod, string
createFunc? hmod, string, '&string'
endm

; void *__fastcall get_hmod(const wchar_t *)
extern ?get_hmod@@YIPAXPB_W@Z : PROC

; void *__fastcall GetFuncAddressEx(struct _IMAGE_DOS_HEADER *,const char *)
extern ?GetFuncAddressEx@@YIPAXPAU_IMAGE_DOS_HEADER@@PBD@Z : PROC

; ecx -> hmod, edx -> func
common_imp_call proc private
  mov eax,[edx] ; eax = func
  test eax,eax ; we already have func address ?
  jnz @@1
  push edx
  mov eax,[ecx] ; eax = hmod
  test eax,eax ; we already load dll ?
  jnz @@2
  push ecx
  lea ecx,[ecx + 4]
  call ?get_hmod@@YIPAXPB_W@Z
  pop ecx
  mov [ecx],eax ; hmod = get_hmod, save dll address
  mov edx,[esp]
@@2:
  lea edx,[edx + 4]
  mov ecx,eax
  call ?GetFuncAddressEx@@YIPAXPAU_IMAGE_DOS_HEADER@@PBD@Z
  pop edx
  mov [edx],eax ; func = GetFuncAddressEx, save func address
@@1:
  pop edx
  pop ecx
  jmp eax
common_imp_call endp

; void *__fastcall __Address(const void * pv)
; do relocation in runtime
; pv : address valid with preffered base
; return : actual address inside ShellCode

?__Address@@YIPAXPBX@Z proc
	call @@0
@@0:
	pop eax
	lea edx,?__Address@@YIPAXPBX@Z
	sub ecx,edx
	lea eax,[ecx + eax - 5]
	ret
?__Address@@YIPAXPBX@Z endp

__chkstk proc
__alloca_probe proc
   push        ecx
   lea         ecx,[esp+4]
   sub         ecx,eax
   sbb         eax,eax
   not         eax
   and         ecx,eax
   mov         eax,esp
   and         eax,0FFFFF000h
@@1:
   cmp         ecx,eax
   jb          @@2
   mov         eax,ecx
   pop         ecx
   xchg        eax,esp
   mov         eax,dword ptr [eax]
   mov         dword ptr [esp],eax
   ret
@@2:
   sub         eax,1000h
   test        dword ptr [eax],eax
   jmp         @@1
__alloca_probe endp
__chkstk endp

IFNDEF _ERW_

_TEXT$cpp$u SEGMENT ALIGN(_ALIGN_)
@imp_begin@ LABEL BYTE
_TEXT$cpp$u ENDS

_TEXT$cpp$v SEGMENT
@imp_end@ LABEL BYTE
_TEXT$cpp$v ENDS

.code

; void *__stdcall GetNtBase()
extern ?GetNtBase@@YGPAXXZ : PROC

protect proc private
	push ecx
	push edx
	
	sub esp,12
	
	lea ecx,@imp_begin@
	test ecx,0FFFh
	jnz @@1
	
	lea edx,@imp_end@
	sub edx,ecx
	
	lea eax,[esp]       ; &OldProtect
	push eax
	
	push 4              ; PAGE_READWRITE
	
	mov [esp + 12],edx	; RegionSize
	
	lea eax,[esp + 12]	; &RegionSize
	push eax
	
	call ?__Address@@YIPAXPBX@Z
	mov [esp + 20],eax ; BaseAddress
	lea eax,[esp + 20] ; &BaseAddress
	push eax

	xor eax,eax
	dec eax				; eax = -1 = NtCurrentProcess()
	push eax

	call ?GetNtBase@@YGPAXXZ
	mov ecx,eax

	call @@0
	DB "ZwProtectVirtualMemory", 0
@@0:
	pop edx
	call ?GetFuncAddressEx@@YIPAXPAU_IMAGE_DOS_HEADER@@PBD@Z
	call eax
@@1:
	add esp,12

	pop edx
	pop ecx
	ret
	
protect endp

ENDIF ; _ERW_




