; From StrMap_Raw_Util -- For easier reference. Trust but verify; always go back to StrMap_Raw_Util.inc to ensure the proper values as they -could- become out of synch during development
; StrMap_Raw offsets
;	strMap_Raw_Offset_Head		equ 0
;	strMap_Raw_Offset_Tail		equ 4
;	strMap_Raw_Offset_Length	equ 8
;	strMap_Raw_Offset_Heap		equ 12

proc StrMap_Raw_Get_HeadPtr	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]
		;;mov edx, [ebx]
		;mov edx, ebx
		

		add edx, [strMap_Raw_Offset_Head]
		mov eax, edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Get_Head	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]
		;mov edx, [ebx]
		

		add eax, [strMap_Raw_Offset_Head]
		mov edx, [eax]
		mov eax, [edx]
	pop edx
	pop ecx
	pop ebx

	ret
endp



proc StrMap_Raw_Get_TailPtr	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]

		add edx, [strMap_Raw_Offset_Tail]
		mov eax, edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Get_Tail	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]

		add eax, [strMap_Raw_Offset_Tail]
		mov edx, [eax]
		mov eax, [edx]
	pop edx
	pop ecx
	pop ebx

	ret
endp



proc StrMap_Raw_Get_LengthPtr	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]

		add edx, [strMap_Raw_Offset_Length]
		mov eax, edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Get_Length	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]

		add eax, [strMap_Raw_Offset_Length]
		mov edx, [eax]
		mov eax, [edx]
	pop edx
	pop ecx
	pop ebx

	ret
endp



proc StrMap_Raw_Get_HeapPtr	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]

		add edx, [strMap_Raw_Offset_Heap]
		mov eax, edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Get_Heap	ptrStrMap_root: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap_root]
		mov edx, [ebx]
		;mov ebx, [edx]

		add eax, [strMap_Raw_Offset_Heap]
		mov edx, [eax]
		mov eax, [edx]
	pop edx
	pop ecx
	pop ebx

	ret
endp