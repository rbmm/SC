.686

.MODEL FLAT

.code

; unsigned long __cdecl istrlen(const char *)
?istrlen@@YAKPBD@Z proc
	mov edx,edi
	mov edi,ecx
	xor al,al
	movzx ecx,al
	dec ecx
	repne scasb
	mov eax,ecx
	neg eax
	dec eax
	dec eax
	mov edi,edx
	ret
?istrlen@@YAKPBD@Z endp

; char __cdecl istrcmp(const char *,const char *)
?istrcmp@@YADPBD0@Z proc
	mov al,[ecx]
	mov ah,[edx]
	cmp al,ah
	jne @@exit
	inc ecx
	inc edx
	test al,al
	jne ?istrcmp@@YADPBD0@Z
	ret
@@exit:
	setg al
	shl al,1
	dec al
	ret
?istrcmp@@YADPBD0@Z endp

end
