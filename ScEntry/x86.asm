.686

.MODEL FLAT

.code

; unsigned long __fastcall istrlen(const char *)
?istrlen@@YIKPBD@Z proc
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
?istrlen@@YIKPBD@Z endp

; char __fastcall istrcmp(const char *,const char *)
?istrcmp@@YIDPBD0@Z proc
	mov al,[ecx]
	mov ah,[edx]
	cmp al,ah
	jne @@exit
	inc ecx
	inc edx
	test al,al
	jne ?istrcmp@@YIDPBD0@Z
	ret
@@exit:
	setg al
	shl al,1
	dec al
	ret
?istrcmp@@YIDPBD0@Z endp

end
