proc FileManager_Get_Files					hFileManager_Obj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]

		mov ecx, ebx
		add ecx, [FileManager_Offset_Files]
		mov eax, [ecx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Get_FileOpen_Count			hFileManager_Obj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]

		mov ecx, ebx
		add ecx, [FileManager_Offset_FilesOpen_Count]
		mov eax, [ecx]
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Get_Heap					hFileManager_Obj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]

		mov ecx, ebx
		add ecx, [FileManager_Offset_Heap]
		mov eax, [ecx]
	pop edx
	pop ecx
	pop ebx

	ret
endp