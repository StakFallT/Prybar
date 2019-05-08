FileManager_Offset_Files				dd 0
FileManager_Offset_FilesOpen_Count		dd (Pointer_Size * 1)
FileManager_Offset_Heap				dd (Pointer_Size * 2)

struct FileManager
	Files				dd	?	; Pointer to StrMap_Element
	FilesOpen_Count	dd	0
	Heap			dd	?
ends

include 'Get\FileManager_Get.inc'
include 'Set\FileManager_Set.inc'


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

	push ebx
		cmp [Heap], NULL
		je FileManager_Create_Use_ProcHeap

	        lea ebx, [Heap]
	       mov ecx, [ebx]
	       mov ebx, [ecx]
		jmp FileManager_Create_Begin_Creation

		FileManager_Create_Use_ProcHeap:
			invoke GetProcessHeap
				mov ebx, eax

		FileManager_Create_Begin_Creation:
			; Create the FileManager object instance using the Heap parameter passed into the function
				invoke HeapAlloc, ebx, NULL, sizeof.FileManager

					push eax
						stdcall FileManager_Clear, eax
					pop eax

					; Get a copy of the address of the heap that is being used and store a copy of that address in strMap_Raw's Heap member
						;add eax, [FileManager_Offset_Heap]
						;mov [eax], ebx
						;sub eax, [FileManager_Offset_Heap]

					; Store that heap address also in FileManager's Heap member (for functions that use it like FileManager_Open_File)
						push eax
							stdcall FileManager_Set_Heap, eax, ebx
						pop eax
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
					push ebx										; ebx is the address of FileManager
						add ebx, [FileManager_Offset_Heap]				; ebx is the address of FileManager. Go to the heap member to get the heap address we are using
						invoke HeapAlloc, [ebx], NULL, sizeof.File

						mov edx, eax								; Store a copy of the address, to the File object instance, in edx for easier reference when the File object instance's members get filled in 
					pop ebx										; Restore ebx to the newly created StrMap (first element)

			; TODO: [PROBLEM]: Currently StrMap is NOT created, thus the file member is NOT managed under StrMap. This needs to be fixed so that operations through
			;			        FileManager go through StrMap. However, the is a design puzzle to be solved of whether create should create the raw member as well as
			;			        an empty element. Presently, the next two lines store the newly created instance of a File object in FileManager's Files member. It should
			;			        be storing the StrMap's first element address instead (and then operations on the file would go through the StrMap_Element's Element
			;			       member. 
				; Store the address of the newly created File object
				; instance in the StrMap (Files) element member
					add ebx, [FileManager_Offset_Files]					; ebx is the newly created StrMap (first element)
					mov [ebx], eax									; StrMap_Element's Element member will now point to the newly created File object instance



			; Next, fill out the File object (currently should be ebx) instance's members

				; For reference:
				;	File 			object instance address: 		eax, edx
				;	FileManager 	object instance address:		ebx

				; First, open the file
					; TODO: [FUNCTIONALITY]: Implement generating the path + filename in unicode (string concatenation) form so it can be used with CreateFile API
					push edx

					push eax
					push ecx
						xor ecx, ecx
						lea ecx, [Payload_File]
						invoke CreateFile, Payload_File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
						mov [hFile], eax
					pop ecx
					pop eax

					pop edx

				; ebx currently points to the FileManager object instance, it needs to point to a File object instance!
 
				; TODO: [CODE_CLEANUP]: Each of these member setting operations could be split into their own functions?...
				; Set the File's hFileHandle member
					push edx

					push ecx
					push ebx
						lea ebx, [hFile]
						mov ecx, [ebx]
						mov ebx, ecx
						stdcall File_Set_hFileHandle, edx, ebx
					pop ebx
					pop ecx

					pop edx									; Restore edx to point back to the File object instance

				; Set the File's UID member
					push edx									; edx is set to the address of the File object instance

					push ecx									; ecx should be free to use
					push ebx									; ebx should currently be set to the address of the newly created StrMap_Element
						lea ebx, [UID]
						mov ecx, [ebx]
						mov ebx, ecx
						stdcall File_Set_UID, edx, ebx
					pop ebx
					pop ecx

					pop edx

				; Set the File's Path member
					push edx									; edx is set to the address of the File object instance

					push ecx									; ecx should be free to use
					push ebx									; ebx should currently be set to the address of the newly created StrMap_Element
						lea ebx, [Path]
						mov ecx, [ebx]
						mov ebx, ecx
						stdcall File_Set_Path, edx, ebx
					pop ebx
					pop ecx

					pop edx

				; Set the File's Filename member
					push edx									; edx is set to the address of the File object instance

					push ecx									; ecx should be free to use
					push ebx									; ebx should currently be set to the address of the newly created StrMap_Element
						lea ebx, [Filename]
						mov ecx, [ebx]
						mov ebx, ecx
						stdcall File_Set_Filename, edx, ebx
					pop ebx
					pop ecx

					pop edx

	ret
endp

proc FileManager_Get_File_ByIndex

endp

proc FileManager_Get_File_ByUID

endp

proc FileManager_Close_File_ByIndex

endp

proc FileManager_Close_File_ByUID

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