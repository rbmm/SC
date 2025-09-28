.CODE

; char __cdecl istrcmp(const char *,const char *)
?istrcmp@@YADPEBD0@Z proc
	mov al,[rcx]
	mov ah,[rdx]
	cmp al,ah
	jne @@exit
	inc rcx
	inc rdx
	test al,al
	jne ?istrcmp@@YADPEBD0@Z
	ret
@@exit:
	setg al
	shl al,1
	dec al
	ret
?istrcmp@@YADPEBD0@Z endp

; unsigned long __cdecl istrlen(const char *)
?istrlen@@YAKPEBD@Z proc
	mov rdx,rdi
	mov rdi,rcx
	xor al,al
	movzx ecx,al
	dec ecx
	repne scasb
	mov eax,ecx
	neg eax
	dec eax
	dec eax
	mov rdi,rdx
	ret
?istrlen@@YAKPEBD@Z endp

end