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

proc StrMap_Element_Get_map_Raw	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, [edx]

		add ebx, [strMap_Element_Offset_map_Raw]
		mov eax, ebx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Head	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		add edx, [strMap_Element_Offset_Head]
		mov ebx, [edx]

		;add ebx, [strMap_Element_Offset_Head]
		;mov eax, ebx
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Name	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, [edx]

		add ebx, [strMap_Element_Offset_Name]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Element	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, edx

		add ebx, [strMap_Element_Offset_Element]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Tail	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, [edx]

		add ebx, [strMap_Element_Offset_Tail]
		mov eax, ebx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Prev	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, edx

		add ebx, [strMap_Element_Offset_Prev]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Next	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, edx

		add ebx, [strMap_Element_Offset_Next]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Element_Get_Length	ptrStrMap: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
		mov edx, [ebx]
		mov ebx, [edx]

		add ebx, [strMap_Element_Offset_Length]
		mov eax, ebx
	pop edx
	pop ecx
	pop ebx

	ret
endp