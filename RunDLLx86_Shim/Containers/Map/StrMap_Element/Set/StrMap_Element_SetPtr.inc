proc StrMap_Element_Set_mapRawPtr	ptrStrMap: DWORD, ptrStr_mapRaw: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
				mov edx, [ebx]
			add edx, [strMap_Element_Offset_map_Raw]
		mov ebx, edx
		; ebx: is now sitting at the map_Raw member of StrMap

			lea edx, [ptrStr_mapRaw]
			push ecx
				mov ecx, [edx]
				mov edx, [ecx]  ; edx will now equal the address of where the StrMap_root is
				mov ecx, [edx]
				; Add the relevant offset, if necessary, here...
				; ...
				mov edx, ecx
			pop ecx
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

; Calling Set Head on an element object should set the address stored by the object's head member to the address of the raw head member.
; When Get Head is called, the indirection should occur automatically and return back the head element and not the raw head member address. 
proc StrMap_Element_Set_HeadPtr	ptrStrMap: DWORD, ptrStrMap_Head: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
				mov edx, [ebx]
			add edx, [strMap_Element_Offset_Head]
		mov ebx, edx
		; ebx: is now sitting at the head member of StrMap

			lea edx, [ptrStrMap_Head]
			push ecx
				mov ecx, [edx]
				mov edx, [ecx]  ; edx will now equal the address of where the StrMap_root is
				mov ecx, [edx]
				; Add the relevant offset, if necessary, here...
				; ...
				mov edx, ecx
			pop ecx
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp

 
proc StrMap_Element_Set_TailPtr	ptrStrMap: DWORD, ptrStrMap_Tail: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
				mov edx, [ebx]
			add edx, [strMap_Element_Offset_Tail]
		mov ebx, edx
		; ebx: is now sitting at the tail member of StrMap

			lea edx, [ptrStrMap_Tail]
			;push ecx
				mov ecx, [edx]
				;mov edx, [ecx]  ; edx will now equal the address of where the StrMap_root is
				;mov ecx, [edx]
				; Add the relevant offset, if necessary, here...
				; ...
				;mov edx, ecx
			;pop ecx
		mov [ebx], ecx
	pop edx
	pop ecx
	pop ebx

	ret
endp


proc StrMap_Element_Set_LengthPtr	ptrStrMap: DWORD, ptrStrMap_Length: DWORD
	push ebx
	push ecx
	push edx
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		lea ebx, [ptrStrMap]
				mov edx, [ebx]
			add edx, [strMap_Element_Offset_Tail]
		mov ebx, edx
		; ebx: is now sitting at the length member of StrMap

			lea edx, [ptrStrMap_Length]
			push ecx
				mov ecx, [edx]
				mov edx, [ecx]  ; edx will now equal the address of where the StrMap_root is
				mov ecx, [edx]
				; Add the relevant offset, if necessary, here...
				add ecx, strMap_Raw_Offset_Tail
				mov edx, ecx
			pop ecx
		mov [ebx], edx
	pop edx
	pop ecx
	pop ebx

	ret
endp
