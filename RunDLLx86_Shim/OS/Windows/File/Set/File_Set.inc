proc File_Set_UID			hFileObj: DWORD, UID: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]

		lea edx, [UID]
		mov ecx, [edx]

		add ebx, [File_Offset_UID]
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc File_Set_Path			hFileObj: DWORD, Path: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]

		lea edx, [Path]
		mov ecx, [edx]

		add ebx, [File_Offset_Path]
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc File_Set_Filename		hFileObj: DWORD, Filename: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]

		lea edx, [Filename]
		mov ecx, [edx]

		add ebx, [File_Offset_Filename]
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc File_Set_hFileHandle		hFileObj: DWORD, hFileHandle: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileObj]
		mov ebx, [ecx]

		lea edx, [hFileHandle]
		mov ecx, [edx]

		add ebx, [File_Offset_hFileHandle]
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp