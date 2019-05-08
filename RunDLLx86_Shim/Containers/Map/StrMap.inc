; FILE: StrMap.inc

include 'StrMap_Util.inc'

;ProcessHeap	dd	?

STRMAP_RAW			equ	0
STRMAP_ELEMENT		equ 	1

strMap_Offset_Type		dd (Pointer_Size * 0)

;proc StrMap_Create		raw_Head, raw_Tail, raw_Length: DWORD
proc StrMap_Create		Heap: DWORD
local ProcessHeap:DWORD

     push ebx
     push ecx
     push edx

        xor ebx, ebx
        xor ecx, ecx
	xor edx, edx

	cmp [Heap], NULL
	je StrMap_Create_Use_ProcHeap

        lea ebx, [Heap]
        mov ecx, [ebx]
        mov ebx, [ecx]

	;invoke HeapAlloc, Heap, HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, sizeof.strMap_Raw
    invoke HeapAlloc, ebx, NULL, sizeof.strMap_Raw
		push ebx
		push ecx
			push eax
				push eax
				call StrMap_Raw_Clear
			pop eax

			lea ecx, [Heap]
			mov ebx, [ecx]

			; Get a copy of the address of the heap that is being used and store a copy of that address in strMap_Raw's Heap member
				add eax, [strMap_Raw_Offset_Heap]
				mov [eax], ebx
				sub eax, [strMap_Raw_Offset_Heap]
		pop ecx
		pop ebx

	; Next, allocate an empty StrMap_Element
		mov edx, eax		;Preserve the eax register (which is set to the address of the newly created strMap_Raw instance)
		push edx			;Preserve the edx register since many of Microsoft's API calls like to trample edx...
		invoke HeapAlloc, ebx, NULL, sizeof.StrMap_Element
		pop edx			; Restore the edx register		so that is is then pointing back at strMap_Raw again
						;						At this point:
						;							edx:			pointer to strMap_Raw
						;						 	eax:			pointer to StrMap_Element

		push ebx
		push ecx
			mov [edx], eax		;Set strMap_Raw's head to point to the created StrMap_Element's map_Raw member
			mov [eax], edx		;Set StrMap_Element's map_Raw member to point to the created strMap_Raw instance

			push edx
			push eax
			call StrMap_Element_Initialize

			push eax
			call StrMap_Element_Increase_Length

		pop ecx
		pop ebx

	pop edx
	pop ecx
	pop ebx

	ret

	StrMap_Create_Use_ProcHeap:
		invoke GetProcessHeap
			push ebx
			mov ebx, eax

		invoke HeapAlloc, ebx, NULL, sizeof.strMap_Raw
			push ecx	

				push eax
					push eax
					call StrMap_Raw_Clear
				pop eax

				; Get a copy of the address of the heap that is being used and store a copy of that address in strMap_Raw's Heap member
					add eax, [strMap_Raw_Offset_Heap]
					mov [eax], ebx
					sub eax, [strMap_Raw_Offset_Heap]
			pop ecx
			pop ebx

		; Next, allocate an empty StrMap_Element
			mov edx, eax		;Preserve the eax register (which is set to the address of the newly created strMap_Raw instance)
			push edx			;Preserve the edx register since many of Microsoft's API calls like to trample edx...
			invoke HeapAlloc, ebx, NULL, sizeof.StrMap_Element
			pop edx			; Restore the edx register		so that is is then pointing back at strMap_Raw again
							;						At this point:
							;							edx:			pointer to strMap_Raw
							;						 	eax:			pointer to StrMap_Element

			push ebx
			push ecx
				mov [edx], eax		;Set strMap_Raw's head to point to the created  StrMap_Element's map_Raw member
				mov [eax], edx		;Set StrMap_Element's map_Raw member to point to the created strMap_Raw instance

				push edx
				push eax
				call StrMap_Element_Initialize

				push eax
				call StrMap_Element_Increase_Length

			pop ecx
			pop ebx

		pop edx
		pop ecx
		pop ebx

		ret
endp

proc StrMap_Initialize		ptrStrMap_raw: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

	pop edx
	pop ecx
	pop ebx

	ret
endp


proc 	StrMap_Initial_Set		ptrStrMap_raw: DWORD, Index:DWORD, Element:DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx


		;Get the StrMap_raw address from the existing element
			lea ecx, [ptrStrMap_raw]

		; (Perform one more indirection before calling to Get_map_Raw)
			mov ebx, [ecx]
			push ebx
				add ebx, [strMap_Raw_Offset_Tail]
				mov ecx, [ebx]
			pop ebx


		push ecx

		; Initialize the 1st StrMap_Element
			;push ecx
			;call StrMap_Element_Get_map_Raw		; Get the address of the ("static") map_Raw instance
			;mov ecx, eax

			;push ecx
			;push [New_StrMapElement]
			push ebx
			push ecx
			call StrMap_Element_Initialize

		pop ecx

	         ; Set the value of the element's name member
	                lea ebx, [Index]
	                mov edx, [ebx]

	                push edx
	                push ecx
	                call StrMap_Element_Set_Name

	pop edx
	pop ecx
	pop ebx

	ret
endp


proc StrMap_Add		ptrStrMap: DWORD, Index: DWORD, Element: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx


		lea ecx, [ptrStrMap]
		mov ebx, [ecx]
		mov ecx, [ebx]

		stdcall StrMap_Get_Type,ecx
		cmp eax, STRMAP_RAW
		je StrMap_SetInitial
		
		StrMap_AddElement:
			stdcall StrMap_Add_Element, [ptrStrMap],[Index],[Element]
			jmp StrMap_Add_Done

		StrMap_SetInitial:
 			stdcall StrMap_Initial_Set, [ptrStrMap],[Index],[Element]

	StrMap_Add_Done:
	pop edx
	pop ecx
	pop ebx

	ret
endp

; Add element to tail of linked-list (Insert would insert into the linked-list)
; ptrStrMap: 	Handle to existing StrMap that has already been created
; Index: 		Pointer to null-terminated string
; Element:		Pointer to element being added 
proc StrMap_Add_Element		ptrStrMap: DWORD, Index: DWORD, Element: DWORD
;local ptrStrMap_Root: strMap_Raw
local New_StrMapElement: DWORD

	push ebx
	push ecx

	push edx

		; Retrieve the heap address being used the call to HeapAlloc will allocate from the proper pool of memory
			lea ecx, [ptrStrMap]
			mov ebx, [ecx]
			mov ecx, [ebx]
			mov ebx, ecx
			add ebx, [strMap_Raw_Offset_Heap]				; jump to member holding address of heap
			mov ecx, [ebx]

		;invoke HeapAlloc, ecx, HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, sizeof.StrMap_Element
		invoke HeapAlloc, [ecx], NULL, sizeof.StrMap_Element
		mov [New_StrMapElement], eax
		; Done with the heap address (ecx) now...



		; At this point in the code-flow of this function:
		; 	New_StrMapElement.map_Raw: 	eax
		; 	ptrStrMap_root.rawHead: 			ebx



		;Get the StrMap_raw address from the existing element
			lea ecx, [ptrStrMap]

		; (Perform one more indirection before calling to Get_map_Raw)
			mov ebx, [ecx]
			mov ecx, ebx



		; Initialize the New_StrMapElement now that its memory has been allocated
			push ecx
			call StrMap_Element_Get_map_Raw		; Get the address of the ("static") map_Raw instance
			mov ecx, eax

			push ecx
			push [New_StrMapElement]
			call StrMap_Element_Initialize

        ; Set the value of the element's name member
            push ebx
            push ecx
            push edx
                lea ecx, [ptrStrMap]
                mov ebx, [ecx]
			    mov ecx, ebx

                lea ebx, [Index]
                mov edx, [ebx]
                push edx
                push ecx
                call StrMap_Element_Set_Name
            pop edx
            pop ecx
            pop ebx

		; Update the Head of the map_Raw and the Raw of the New Element
			;mov edx, [New_StrMapElement]
			; Update map_raw.rawHead to point to the New Element and vice-versa		StrMap_root.rawHead -> New_StrMapElement
			;	mov [ecx], edx
	            	;	mov [edx], ecx

	pop edx

		; At this point in the code-flow of this function:
		;	ecx: StrMap container's ?
		;	ebx: StrMap container's ?

		; strMap_Raw
	;	.rawHead
	;	.rawTail
	;	.rawLength
	;	.rawHeap

		; StrMap_Element
		;	[ .map_Raw 	-----------------------------]-------------> [ .rawHead	 (techinically $) ]
		;	[ .Head		(technically $+4)	|		 | .rawTail	 	($+4) 	        |
		;	[ .Name		($+8)				|		 | .rawLength 	($+8)		        |
		;	[ .Element	($+12)				|		 [ .rawHeap	($+12)	        ]
		;	[ 							|
		;	[ .Tail		($+16)			|
		;	[							|
		;	[ .Prev		($+20)			|
		;	[ .Next		($+24)			|
		;	[							|
		;	[ .Length	($+28)				]

		; ecx is currently pointing at map_Raw

		;  Update the old tail's members to reflect that it is no longer the tail
			push ebx
			push ecx
			push edx

				;Get the StrMap_raw address from the existing element
					lea ecx, [ptrStrMap]
		
				; (Perform one more indirection before calling to Get_map_Raw)
					mov edx, [ecx]

					push edx
					call StrMap_Element_Get_map_Raw		; Get the address of the ("static") map_Raw instance
					mov ecx, eax




;TODO: [BUG]: Tail is being set to the first instance address (same as head) instead of the last instance address
			;Update the tail pointers
				; Get the address of the ("static") raw section's Tail member so the New Element's Tail member can point to it
					;call StrMap_Raw_Get_HeadPtr
					push ecx
					call StrMap_Raw_Get_TailPtr

				; Set the New Element's tail member to point to the ("static") raw section's Tail member
					push eax
					push [New_StrMapElement]
					;call StrMap_Element_Set_HeadPtr
					call StrMap_Element_Set_TailPtr

				; Set map_Raw's Tail value to point to the New Element
				        push [New_StrMapElement]
						lea ecx, [ptrStrMap]
						mov edx, [ecx]
						push edx
					call StrMap_Raw_Set_Tail 

			;TODO: Update the Head pointers
				; Update the Head member of the ("static") raw section
				;	...



				; Update Tail member of the ("static") raw section
					;lea ecx, [ptrStrMap]							; Get the address of the existing element that was passed into the function (for the purposes of referencing the same strMap_Raw instance
					;add ecx, Pointer_Size							; For reference: Pointer_Size		equ 4
					;	push edx
					;		lea edx, [ebx + 16]
					;		add eax, [strMap_Raw_Offset_Tail]
					;			mov [eax], ecx					; New_StrMapElement.Tail (ebx+16 = &ptrStrMap_root.rawTail
					;		sub eax, [strMap_Raw_Offset_Tail]
					;	pop edx
					;sub ecx, Pointer_Size



				; Update Prev
					push ecx
					push edx
						lea ecx, [New_StrMapElement]
						mov edx, [ecx]
						add edx, [strMap_Element_Offset_Prev]
						mov [edx], ebx
					pop edx
					pop ecx



				; Update previous element's Next member to point to this New Element
					push eax
					push ebx

; TODO: [BUG]: For some reason this sets the Next-member's value to an address that isn't exactly correct, it also sets the next's map_Raw member's value to the same address that isn't exactly correct.
					push ecx
					push edx
						lea eax, [ptrStrMap]
						mov ebx, [eax]
						add ebx, [strMap_Element_Offset_Next]	; Get to the Next member of the previous element
						mov eax, ebx						; Store the previous element's Next member address in the eax register 

						lea ecx, [New_StrMapElement]
						mov edx, [ecx]
						mov ecx, edx

						mov [eax], ecx						; Stoe the New Element's address in the address sitting in eax register which is the address of the previous element's Next member
					pop edx
					pop ecx

					pop ebx
					pop eax


				; Increment Length by 1
					lea ecx, [ptrStrMap]
					mov ebx, [ecx]
					mov ecx, ebx

					push ecx
					call StrMap_Element_Get_map_Raw

					;push eax
					;call StrMap_Raw_Increase_Length
					push ecx
					call StrMap_Element_Increase_Length



				; Update Length member of New_StrpMapElement to point to the raw_Length
				;	lea ecx, [ptrStrMap]
				;	add ecx, 8
				;	push edx
				;	    lea edx, [ebx]
				;		add edx, 28
				;	    mov [eax], ecx				; New_StrMapElement.Length (ebx+28) = &ptrStrMap_root.rawLength
				;		sub edx, 28
				;	pop edx
				;	sub ecx, 8

                ;pop edx
		;pop ecx
		;pop ebx



			; Update the tail now to reflect the 'new' last element
				;lea ecx, [ptrStrMap.map_Raw.rawTail]
			;	lea ecx, [ptrStrMap + 28]
			;	mov edx, [ecx]
			;	mov ecx, [edx]
			;	;mov [Old_StrMap_Tail], ecx
			;	mov [ecx], ebx 

			pop edx
			pop ecx
			pop ebx

	; ebx is already set to ptrStrMap

	; Set the head
	;	push ebx
	;	push ecx

	;	lea ebx, [ptrStrMap.Head]
	;	lea edx, [New_StrMapElement.Head]
	;	mov [edx], ebx



	; Set the tail
	; Set the prev
	; Set the next

	; Finally, set the Index and the element



	pop ecx
	pop ebx

	mov eax, [New_StrMapElement]

	ret
endp

proc StrMap_Set_Type	rawPtr: DWORD, Type: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

	lea ecx, [rawPtr]
	mov ebx, [ecx]
	add ebx, [strMap_Offset_Type]

	lea ecx, [Type]
	mov edx, [ecx]
	mov [ebx], edx

	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Get_Type	rawPtr: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

	lea ecx, [rawPtr]
	mov ebx, [ecx] 
	add ebx, [strMap_Offset_Type]
	mov eax, [ebx]

	pop edx
	pop ecx
	pop ebx

	ret
endp

proc StrMap_Next	ptrStrMap_Element: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, ptrStrMap_Element
		mov ecx, [ebx]
		mov ebx, ecx

		add ebx, [strMap_Element_Offset_Next]
		mov ecx, [ebx]
		mov eax, [ecx]
	pop edx
	pop ecx
	pop ebx

	ret
endp