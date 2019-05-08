proc FileManager_Set_Files					hFileManager_Obj: DWORD, FilesAddr: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]
		add ebx, [FileManager_Offset_Files]
		mov edx, [ebx]

		lea ecx, [FilesAddr]
		mov ebx, [ecx]
		mov [edx], ebx

		mov eax, 0
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Set_FileOpen_Count			hFileManager_Obj: DWORD, FileCount: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx 
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]
		add ebx, [FileManager_Offset_FilesOpen_Count]
		mov edx, [ebx]

		lea ecx, [FileCount]
		mov ebx, [ecx]

		mov eax, 0
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Set_Heap					hFileManager_Obj: DWORD, HeapAddr: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]
		add ebx, [FileManager_Offset_Heap]
		;mov edx, [ebx]
		mov edx, ebx

		lea ecx, [HeapAddr]
		mov ebx, [ecx]
		mov [edx], ebx

		mov eax, 0
	pop edx
	pop ecx
	pop ebx

	ret
endp