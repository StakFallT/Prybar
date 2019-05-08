STR_NEQ		equ	-1
STR_EQ		equ	0

; Description: Compare two strings and return whether they are equal or not. NOTE: This is case sensitive!
; Parameters:
;	srcStr: 	Address of string to test
;	destStr: 	Address of string to compare with
; Return stored in EAX
; Return values:
;	EAX: FFFFFFFF	- Not equal
;	EAX: 00000000	- Equal
proc Is_StrEqual	srcStr, destStr: DWORD
	push ebx
	push ecx
	push edx

	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx

		push esi
		push edi

			xor esi, esi
			xor edi, edi

			lea ebx, [srcStr]
			mov esi, [ebx]

			lea edx, [destStr]
			mov edi,  [edx]

		StrCompare_Begin:
			; sil and dil registers can only be used when REX bits are set (i.e. 64-bit) , so we'll need to re-use esi and eax
				;mov sil, [bl]
				;mov dil, [dl]
	
				;cmp si, di

			xor eax, eax	; clear our temporary variable (register)
			xor ebx, ebx	; Again, clear our (other) temporary variable (register)

			;push esi
			;	lodsb
			;	mov bl, al

			;	mov esi, ...
			;
			; Better plan... use esi and edi and xchg between them :)
			lodsb
			mov bl, al
			xchg edi, esi
			lodsb
			mov cl, al
			cmp bl, cl
			jne StrCompare_NotEq
			cmp bl, 0x00
			je StrCompare_DefaultEq
			add ebx, 1
			add edx, 1
			jmp StrCompare_Begin

		StrCompare_NotEq:
			mov eax, STR_NEQ
			jmp StrCompare_End

		StrCompare_DefaultEq:
			mov eax, STR_EQ

		StrCompare_End:

			pop edi
			pop esi

			pop edx
			pop ecx
			pop ebx

			ret
endp