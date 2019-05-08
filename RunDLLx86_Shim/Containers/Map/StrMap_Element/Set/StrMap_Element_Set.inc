; From StrMap_Element_Util -- For easier reference. Trust but verify; always go back to StrMap_Element_Util.inc to ensure the proper values as they -could- become out of synch during development
; NOTE: Pointer_Size is from Globals.inc

; StrMap_Element offsets
	;strMap_Element _Offset_map_Raw		equ 0
	;strMap_Element _Offset_Head			equ 4
	;strMap_Element _Offset_Name			equ 8
	;strMap_Element _Offset_Element		equ 12
	;strMap_Element _Offset_Tail			equ 16
	;strMap_Element _Offset_Prev			equ 20
	;strMap_Element _Offset_Next			equ 24
	;strMap_Element _Offset_Length			equ 28

	;strMap_Element_Offset_map_Raw		equ 0
	;strMap_Element_Offset_Head			equ ([Pointer_Size] * 1)
	;strMap_Element_Offset_Name			equ ([Pointer_Size] * 2)
	;strMap_Element_Offset_Element		equ ([Pointer_Size] * 3)
	;strMap_Element_Offset_Tail			equ ([Pointer_Size] * 4)
	;strMap_Element_Offset_Prev			equ ([Pointer_Size] * 5)
	;strMap_Element_Offset_Next			equ ([Pointer_Size] * 6)
	;strMap_Element_Offset_Length			equ ([Pointer_Size] * 7)

proc StrMap_Element_Set_map_Raw	ptrStrMap: DWORD, ptrStrMap_Raw: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, [strMap_Element_Offset_map_Raw]
		mov ebx, edx
		lea edx, [ptrStrMap_Raw]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Set_Name	ptrStrMap: DWORD, ptrStrMap_Name: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, [strMap_Element_Offset_Name]
		mov ebx, edx
		lea edx, [ptrStrMap_Name]
		mov ecx, [edx]
		mov edx, ecx
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Set_Element	ptrStrMap: DWORD, ptrStrMap_Element: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, [strMap_Element_Offset_Element]
		mov ebx, edx
		lea edx, [ptrStrMap_Element]
		mov ecx, [edx]
		mov edx, ecx
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Set_Tail	ptrStrMap: DWORD, ptrStrMap_Tail: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, [strMap_Element_Offset_Tail]
		mov ebx, edx
		lea edx, [ptrStrMap_Tail]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Set_Prev	ptrStrMap: DWORD, ptrStrMap_Prev: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, strMap_Element_Offset_Prev
		mov ebx, edx
		lea edx, [ptrStrMap_Prev]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Set_Next	ptrStrMap: DWORD, ptrStrMap_Next: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, strMap_Element_Offset_Next
		mov ebx, edx
		lea edx, [ptrStrMap_Next]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Set_Length	ptrStrMap: DWORD, ptrStrMap_Length: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]

		add edx, strMap_Element_Offset_Length
		mov ebx, edx
		lea edx, [ptrStrMap_Length]
		mov ecx, [edx]
		mov edx, [ecx]
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp