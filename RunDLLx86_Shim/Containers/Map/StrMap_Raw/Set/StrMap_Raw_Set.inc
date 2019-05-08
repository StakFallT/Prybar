; FILE: StrMap_Raw_Set.inc

; From StrMap_Raw_Util -- For easier reference. Trust but verify; always go back to StrMap_Raw_Util.inc to ensure the proper values as they -could- become out of synch during development
; StrMap_Raw offsets
;	strMap_Raw_Offset_Head		equ 0
;	strMap_Raw_Offset_Tail		equ 4
;	strMap_Raw_Offset_Length	equ 8
;	strMap_Raw_Offset_Heap		equ 12

proc StrMap_Raw_Set_Head	ptrStrMap_root: DWORD, ptrRaw_Head:DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]
		add edx, [strMap_Raw_Offset_Head]
		mov ebx, edx

		;mov [ebx], ptrRaw_Head
		lea edx, [ptrRaw_Head]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

;proc StrMap_Raw_Set_Tail	ptrStrMap_root: DWORD, ptrRaw_Tail:DWORD
proc StrMap_Raw_Set_Tail	ptrStrMap: DWORD, ptr_NewTail:DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		; Get the address the existing map's map_Raw member is pointing to
			lea ebx, [ptrStrMap]
			mov edx, [ebx]
			mov ebx, [edx]
			add ebx, [strMap_Raw_Offset_Tail]

		lea edx, [ptr_NewTail]
		mov ecx, [edx]

		; Set the map_Raw member's value to the address of the new tail
		;mov edx, [ecx]
		;mov [ebx], edx
			mov [ebx], ecx

	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Set_Length	ptrStrMap_root: DWORD, ptrRaw_Length:DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]

		add edx, [strMap_Raw_Offset_Length]
		mov ebx, edx
		;mov [ebx], ptrRaw_Length
		lea edx, [ptrRaw_Length]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Set_Heap	ptrStrMap_root: DWORD, ptrRaw_Heap:DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]

		add edx, [strMap_Raw_Offset_Heap]
		mov ebx, edx
		;mov [ebx], ptrRaw_Heap
		lea edx, [ptrRaw_Heap]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Set_LengthValue	ptrStrMap_root: DWORD, LengthValue: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		add edx, [strMap_Raw_Offset_Length]
		mov ebx, edx

		lea ecx, [LengthValue]
		mov edx, [ecx]
		mov ebx, [edx]
	pop edx
	pop ecx
	pop ebx

	ret
endp