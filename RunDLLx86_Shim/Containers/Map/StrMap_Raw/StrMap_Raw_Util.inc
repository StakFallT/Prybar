; StrMap_Raw offsets
	
	strMap_Raw_Offset_Head		dd (Pointer_Size * 1)
	strMap_Raw_Offset_Tail		dd (Pointer_Size * 2)
	strMap_Raw_Offset_Length	dd (Pointer_Size * 3)
	strMap_Raw_Offset_Heap		dd (Pointer_Size * 4)

; Contains the raw values of where the respective members in StrMap_Element point to
struct strMap_Raw
	rawHead		dd	0	; Pointer to the variable that contains the address to the head 		-- this way the head can be removed and not every element needs to be updated
	rawTail		dd 	0	; Pointer to the variable that contains the address to the tail 		-- this way the tail can be removed and not every element needs to be updated
	rawLength		dd	0	; Pointer to the variable that contains the address to the length 	-- this way elements can be added and removed without every element needing updating
	rawHeap		dd	0	; Pointer to the heap that will be used when allocating new elements -- Not referenced in StrMap_Element!
ends

include 'Get\StrMap_Raw_Get.inc'
include 'Set\StrMap_Raw_Set.inc'


proc StrMap_Raw_Clear 	ptrStrMap_root: DWORD
	push ebx
	push ecx
		xor ebx, ebx
		xor ecx, ecx

		lea ebx, [ptrStrMap_root]
		mov ecx, [ebx]
		;mov ebx, [ecx]

		mov ebx, ecx

		add ebx, [strMap_Raw_Offset_Head]
		mov [ebx],dword 0

		mov ebx, ecx
		add ebx, [strMap_Raw_Offset_Tail]
		mov [ebx],dword 0

		mov ebx, ecx
		add ebx, [strMap_Raw_Offset_Length]
		mov [ebx],dword 0

		mov ebx, ecx
		add ebx, [strMap_Raw_Offset_Heap]
		mov [ebx],dword 0

		mov ebx, ecx

	pop ecx
	pop ebx

	ret
endp


proc StrMap_Raw_Increase_Length	ptrStrMap_root: DWORD
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
		mov ecx, [ebx]
		;add ecx, dword 1
		add cl, byte 1
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Raw_Decrease_Length	ptrStrMap_root: DWORD
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
		mov ecx, [ebx]
		;sub ecx, dword 1
		;sub ecx, 1
		sub cl, 1
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp