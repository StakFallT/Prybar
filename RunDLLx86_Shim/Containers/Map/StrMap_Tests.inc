proc StrMap_Test

	push ebx
	push ecx
	push edx




	; Test call to length functions
		;push [StrMap]
		push ebx
		push ecx
			xor ebx, ebx
			xor ecx, ecx
			lea ebx, [StrMap]
			mov ecx, [ebx]

			push ecx
			call StrMap_Element_Decrease_Length

			push ecx
			call StrMap_Element_Increase_Length
		pop ecx
		pop ebx

	; Test call to index functions
		push ebx
		push ecx
			xor ebx, ebx
			xor ecx, ecx
			lea ebx, [StrMap]
			mov ecx, [ebx]

			push StrMap_Element_StrIndex0
			push ecx
			call StrMap_Element_Set_Name


            ; Until more error checking is performed in the helper functions, a direct call to setting the element is being made here
            ; to test the Get_Element function
	            push edx
	                lea ebx, [PE_Header_Optional]
	                mov edx, ebx

	                push edx
	                push ecx
	                call StrMap_Element_Set_Element
	            pop edx

            push ecx
            call StrMap_Element_Get_Element

			push ecx
			call StrMap_Element_Get_Next

           push eax
			push StrMap_Element_StrIndex1
			push eax
			call StrMap_Element_Set_Name
           pop eax

           push ecx
            mov ecx, eax
            push ecx
            call StrMap_Element_Get_Prev
           pop ecx

		pop ecx
		pop ebx


    ; Test call to index functions
        push ebx
        push ecx
            xor ebx, ebx
            xor ecx, ecx
            lea ebx, [StrMap]
            mov ecx, [ebx]

            push 1
            push ecx
            call StrMap_Element_Get_ByIndex

            push 0
            push ecx
            call StrMap_Element_Get_ByIndex

            push StrMap_Element_StrIndex1
            push ecx
            call StrMap_Element_Get

            push StrMap_Element_StrIndex0
            push ecx
            call StrMap_Element_Get
        pop ecx
        pop ebx





	pop edx
	pop ecx
	pop ebx

endp