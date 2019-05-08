proc File_Get_UID			hFileObj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]
		add ebx, [File_Offset_UID]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc File_Get_Path			hFileObj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]
		add ebx, [File_Offset_Path]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc File_Get_Filename		hFileObj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]
		add ebx, [File_Offset_Filename]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc File_Get_hFileHandle		hFileObj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]
		add ebx, [File_Offset_hFileHandle]
		mov eax, [ebx]
	pop edx
	pop ecx
	pop ebx

	ret
endp