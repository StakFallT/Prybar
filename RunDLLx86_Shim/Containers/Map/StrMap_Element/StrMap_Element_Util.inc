; NOTE: Pointer_Size is from Globals.inc

; StrMap_Element offsets
	;strMap_Raw_Offset_map_Raw		equ 0
	;strMap_Raw_Offset_Head			equ 4
	;strMap_Raw_Offset_Name			equ 8
	;strMap_Raw_Offset_Element		equ 12
	;strMap_Raw_Offset_Tail			equ 16
	;strMap_Raw_Offset_Prev			equ 20
	;strMap_Raw_Offset_Next			equ 24
	;strMap_Raw_Offset_Length		equ 28

	strMap_Element_Offset_map_Raw		dd (Pointer_Size * 1)			;strMap_Offset_Type is dd 0  (first element)
	strMap_Element_Offset_Head			dd (Pointer_Size * 2)
	strMap_Element_Offset_Name			dd (Pointer_Size * 3)
	strMap_Element_Offset_Element		dd (Pointer_Size * 4)
	strMap_Element_Offset_Tail			dd (Pointer_Size * 5)
	strMap_Element_Offset_Prev			dd (Pointer_Size * 6)
	strMap_Element_Offset_Next			dd (Pointer_Size * 7)
	strMap_Element_Offset_Length			dd (Pointer_Size * 8)

struct StrMap_Element
	; Members to be treated as private:
		map_Raw		dd 	0	; Essentially a private member, that holds a pointer to the raw navigation-member values

	Head		dd	0	; Pointer to the first element

	Name		dd 	0	; Pointer to a null-terminated string that acts as the index
	Element		dd	0	; Needs to remain a dword (pointer) since the size

	Tail			dd	0	; Pointer to the end

	Prev			dd 	0	; Pointer to prev element
	Next			dd  	0	; Pointer to next element
 
	Length		dd 	0	; Number of elements 
ends

include 'Get\StrMap_Element_Get.inc' 
include 'Set\StrMap_Element_Set.inc'
include 'Set\StrMap_Element_SetPtr.inc'


proc StrMap_Element_Initialize		StrMap_element: DWORD,	Str_Map_Raw: DWORD

	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ecx, [StrMap_element]
		mov ebx, [ecx]

		lea edx, [Str_Map_Raw]
		mov ecx, [edx]

		mov [ebx], ecx		; set StrMap_Element's map_Raw member to point to the where Str_Map_Raw is



		push ebx
		push ecx
			add ebx, [strMap_Element_Offset_Head]
			add ecx, [strMap_Raw_Offset_Head]
			mov [ebx], ecx
		pop ecx
		pop ebx



		push ebx
			add ebx, [strMap_Element_Offset_Name]
			mov [ebx], dword 0
		pop ebx

		push ebx
			add ebx, [strMap_Element_Offset_Element]
			mov [ebx], dword 0
		pop ebx



		push ebx
		push ecx
			add ebx, [strMap_Element_Offset_Tail]
			add ecx, [strMap_Raw_Offset_Tail]
			mov [ebx], ecx
		pop ecx
		pop ebx



		push ebx
			add ebx, [strMap_Element_Offset_Prev]
			mov [ebx], dword 0
		pop ebx

		push ebx
			add ebx, [strMap_Element_Offset_Next]
			mov [ebx], dword 0
		pop ebx



		push ebx
		push ecx
			add ebx, [strMap_Element_Offset_Length]
			add ecx, [strMap_Raw_Offset_Length]
			mov [ebx], ecx
		pop ecx
		pop ebx

		mov eax, ebx

	pop edx
	pop ecx
	pop ebx

	ret
endp



proc StrMap_Element_Increase_Length		StrMap_element: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

				lea edx, [StrMap_element]		; edx: will contain address to StrMap_element after this line
			mov ecx, [edx]
			mov ebx, [ecx]
			mov ecx, ebx					; ecx: will contain address to strMap_Raw after this line

		mov ebx, ecx						; ebx: will contain address to ...

		push ebx
		call StrMap_Raw_Increase_Length

	pop edx
	pop ecx
	pop ebx 

	ret
endp


proc StrMap_Element_Decrease_Length		StrMap_element: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

				lea edx, [StrMap_element]		; edx: will contain address to StrMap_element after this line
			mov ecx, [edx]
			mov ebx, [ecx]
			mov ecx, ebx					; ecx: will contain address to strMap_Raw after this line

		mov ebx, ecx						; ebx: will contain address to ...

		push ebx
		call StrMap_Raw_Decrease_Length

	pop edx
	pop ecx
	pop ebx

	ret
endp


proc StrMap_Element_Get_ByIndex	StrMap_element: DWORD, Map_Index: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

				lea edx, [StrMap_element]
			mov ecx, [edx]
		mov ebx, ecx

				lea edx, [Map_Index]
			mov ecx, [edx]
		mov edx, ecx



		mov ecx, 0

		push ebx
		call StrMap_Element_Get_Head
        push edx
            mov edx, [eax]
            mov eax, [edx]
        pop edx

		cmp ecx, edx
		jge Get_ElementByIdx_End		

	; TODO: [BUG]: Length is not checked though if an index is passed higher than the length value of the map this routine will continue to keep attempting to go to the next index
	; TODO: [OPTIMIZATION]: The index could be compared to the length of the map, and if it's closer to the end, the tail could be started at and work backwards.
		Get_ElementByIdx_Start:
			push eax
			call StrMap_Element_Get_Next
			add ecx, 1
			cmp ecx, edx
			jge Get_ElementByIdx_End
			jmp Get_ElementByIdx_Start

		Get_ElementByIdx_End:

	pop edx
	pop ecx
	pop ebx

	ret
endp


proc StrMap_Element_Get					StrMap_element: DWORD, Element_Name: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx


				lea edx, [StrMap_element]
			mov ecx, [edx]
		mov ebx, ecx

				lea edx, [Element_Name]
			mov ecx, [edx]
		mov edx, ecx


        mov ecx, 0

		push ebx
		call StrMap_Element_Get_Head
        push edx
            mov edx, [eax]
            mov eax, [edx]
        pop edx

        push eax
        call StrMap_Element_Get_Name

        push edx
        push eax
        call Is_StrEqual

        cmp eax, STR_EQ
        jge Get_ElementByName_Success
        ;jge Get_ElementByName_End

        Get_ElementByName_Begin:
            ; TODO: [BUG]: Check ecx against length and ensure there IS a next member value of some kind, otherwise the end of the map (linked-list) has been reached.
            ;   ...

            push ebx
            call StrMap_Element_Get_Next
            mov ebx, eax

            push eax
            call StrMap_Element_Get_Name

            push edx
            push eax
            call Is_StrEqual

            cmp eax, STR_EQ
		    jge Get_ElementByName_Success
		    jmp Get_ElementByName_Begin
	; ...

    Get_ElementByName_Success:
        mov eax, ebx

    Get_ElementByName_End:
	    pop edx
	    pop ecx
	    pop ebx

	ret
endp