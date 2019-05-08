FileManager_Offset_Files				dd 0
FileManager_Offset_FilesOpen_Count		dd (Pointer_Size * 1)
FileManager_Offset_Heap				dd (Pointer_Size * 2)

struct FileManager
	Files				dd	?	; Pointer to StrMap_Element
	FilesOpen_Count	dd	0
	Heap			dd	?
ends


proc FileManager_Clear					hFileManager_Obj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]

		push ebx
			add ebx, [FileManager_Offset_Files]
			mov [ebx], dword 0
		pop ebx

		push ebx
			add ebx, [FileManager_Offset_FilesOpen_Count]
			mov [ebx], dword 0
		pop ebx

	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Create					Heap: DWORD
	push ebx
     	push ecx
     	push edx

	        xor ebx, ebx
	        xor ecx, ecx
		xor edx, edx
	
		cmp [Heap], NULL
		je FileManager_Create_Use_ProcHeap
	
	        lea ebx, [Heap]
	        mov ecx, [ebx]
	        mov ebx, [ecx]
		jmp FileManager_Create_Begin_Creation
	
		FileManager_Create_Use_ProcHeap:
			invoke GetProcessHeap
				push ebx
				mov ebx, eax
	
		FileManager_Create_Begin_Creation:
			invoke HeapAlloc, ebx, NULL, sizeof.FileManager
				push ecx	
	
					push eax
						push eax
						call FileManager_Clear
					pop eax
	
					; Get a copy of the address of the heap that is being used and store a copy of that address in strMap_Raw's Heap member
						add eax, [FileManager_Offset_Heap]
						mov [eax], ebx
						sub eax, [FileManager_Offset_Heap]
	
					push eax
						; Store that heap address also in FileManager's Heap member (for functions that use it like FileManager_Open_File)
							push ebx
							push eax
							call FileManager_Set_Heap
					pop eax
	
				pop ecx
				pop ebx

	pop edx
	pop ecx
	pop ebx

	ret
endp


; TODO: [SLOPPY_CODE]: FileManager_Open_File needs to be completely scrapped and redone from scratch. It's an utter mess!
proc FileManager_Open_File					hFileManager_Obj: DWORD, UID: DWORD, Path: DWORD, Filename: DWORD
local hFile: DWORD

	push ebx
     	push ecx
     	push edx

        		xor ebx, ebx
        		xor ecx, ecx
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]


		; UPDATE: Just don't call open without first calling create. Done. Problem fixed, lulz
			; First check if FileManager's StrMap (the Files member) has been created by looking at the number of FilesOpened
			;	lea ecx, [hFileManager_Obj]
			;	mov ebx, [ecx]
	
			;	push ebx
			;	call FileManager_Get_FileOpen_Count
			;	cmp eax, 0
			;	jg FileManager_Open_File_OpenFile		; If FilesOpen_Count is > 0, then safe to call StrMap_Add since StrMap_Element must have been created already at some point


		FileManager_Open_File_OpenFile:
			; Now that the StrMap is, in one way or another, created,
			;	create the File struct object and
			; 	store its address in the StrMap (Files) element member

				; Create the File struct object instance
					push ebx										; ebx is the newly created StrMap (first element)
						add ebx, [FileManager_Offset_Heap]				; ebx is the address of FileManager. Go to the heap member to get the heap address we are using
						push ebx									; Push the heap address onto the stack
						invoke HeapAlloc, ebx, NULL, sizeof.File

						mov edx, eax								; Store a copy of the address, to the File object instance, in edx for easier reference when the File object instance's members get filled in 
					pop ebx										; Restore ebx to the newly created StrMap (first element)

					; Store the address of the newly created File object
					; instance in the StrMap (Files) element member
						add ebx, [strMap_Element_Offset_Element]		; ebx is the newly created StrMap (first element)
						mov [ebx], eax								; StrMap_Element's Element member will now point to the newly created File object instance



			; Next, fill out the File object (currently should be ebx) instance's members

				; For reference:
				;	File object instance address: 		eax, edx
				;	StrMap_Element address:			ebx

				; First, open the file
					; TODO: [FUNCTIONALITY]: Implement generating the path + filename in unicode (string concatenation) form so it can be used with CreateFile API
					push eax
					push ecx
						xor ecx, ecx
						lea ecx, [Payload_File]
						invoke CreateFile, Payload_File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
						mov [hFile], eax
						;push 0
						;call ShowLastError
					pop ecx
					pop eax

				; TODO: [CODE_CLEANUP]: Each of these member setting operations could be split into their own functions...
				; Set the File's hFileHandle member
					push edx
						add edx, [FileManager_Offset_hFileHandle]
						mov [edx], eax							; Store the handle to the newly opened file in the File's hFileHandle member
					pop edx									; Restore edx to point back to the File object instance

				; Set the File's UID member
					push edx				; edx is set to the address of the File object instance

					push ecx				; ecx should be free to use
					push ebx				; ebx should currently be set to the address of the newly created StrMap_Element
						lea ebx, [UID]
						mov ecx, [ebx]
						mov ebx, [ecx]

						add edx, [FileManager_Offset_UID]
					pop ebx
					pop ecx

					pop edx

				; Set the File's Path member
					push edx				; edx is set to the address of the File object instance

					push ecx				; ecx should be free to use
					push ebx				; ebx should currently be set to the address of the newly created StrMap_Element
						lea ebx, [Path]
						mov ecx, [ebx]
						mov ebx, [ecx]

						add edx, [FileManager_Offset_Path]
					pop ebx
					pop ecx

					pop edx

				; Set the File's Filename member
					push edx				; edx is set to the address of the File object instance

					push ecx				; ecx should be free to use
					push ebx				; ebx should currently be set to the address of the newly created StrMap_Element
						lea ebx, [Filename]
						mov ecx, [ebx]
						mov ebx, [ecx]

						add edx, [FileManager_Offset_Filename]
					pop ebx
					pop ecx

					pop edx

	ret
endp

proc FileManager_Close_File_ByIndex

endp

proc FileManager_Close_File_ByUID

endp




proc FileManager_Get_File_ByIndex

endp

proc FileManager_Get_File_ByUID

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
		mov edx, [ebx]

		lea ecx, [HeapAddr]
		mov ebx, [ecx]
		mov [edx], ebx

		mov eax, ebx

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



proc FileManager_Set_FileOpen_Count			hFileManager_Obj: DWORD, FileCount: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx 
		xor edx, edx

		lea ecx, [FileCount]
		mov ebx, [ecx]

		lea edx, [hFileManager_Obj]
		mov ecx, [edx]
		mov [ecx], ebx

	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Increase_FileOpen_Count		hFileManager_Obj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx 
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]
		add ebx, [FileManager_Offset_FilesOpen_Count]
		add [ebx], dword 1
		mov eax, [ebx]
		;mov [ecx], ebx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc FileManager_Decrease_FileOpen_Count		hFileManager_Obj: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx 
		xor edx, edx

		lea ecx, [hFileManager_Obj]
		mov ebx, [ecx]
		add ebx, [FileManager_Offset_FilesOpen_Count]
		sub [ebx], dword 1
		mov eax, [ebx]
		;mov [ecx], ebx
	pop edx
	pop ecx
	pop ebx

	ret
endp