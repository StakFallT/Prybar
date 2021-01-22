;include 'File_Header.inc'

proc Locate_PE32_Header_Offset 	ByteBuffer:DWORD
	push edx
		xor edx, edx

	push esi
	push ecx

		xor ecx, ecx
		xor esi, esi

		lea ecx, [ByteBuffer]
		mov esi, [ecx]
		;lea edx, [ByteBuffer]


		PE_Header_Start_Searching:
			; Looking for PE\0\0 or 0x00004550
			;lodsb

			PE_Header_Is1stByte_50:
				lodsb
				add edx, 0x01
				cmp al, 0x50									;'P'
				jne PE_Header_Start_Searching

				PE_Header_Is2ndByte_45:
					lodsb
					add edx, 0x01
					cmp al, 0x45								;'E'
					;jmp PE_Header_Is4thByte_50
					jne PE_Header_Start_Searching
	
					PE_Header_Is3rdByte_00:
						lodsb
						add edx, 0x01
						cmp al, 0x00							;0x00
						;jmp PE_Header_Is3rdByte_45
						jne PE_Header_Start_Searching
		
						PE_Header_Is4thByte_00:
							lodsb
							add edx, 0x01
							cmp al, 0x00						;0x00
							;jmp PE_Header_Is2ndByte_00
							jne PE_Header_Start_Searching
							; We've reached the end, now subtract 4 off from the counter
								sub edx, 0x04




	pop ecx
	pop esi

	mov eax, edx		;edx represents how many bytes into ByteBuffer the PE header starts at
	pop edx
	ret
endp

; Reads the PE header bytes from an address of a variable into a variable that will hold those values.
;
; Parameters: 
;   ByteBuffer              is the address of the variable containing ALL of the bytes (including the MZ header) -- hence why PE_Header_StartAddress is useful
;   PE_Header_StartAddress  is the address into ByteBuffer where the PE Magic Header starts
;   PE_Header_Storage       is where the values of the members of the PE header will be stored.
proc Read_PE_Header 	ByteBuffer:DWORD, PE_Header_StartAddress:DWORD, PE_Header_Storage:DWORD
	push ebx
    push ecx
    push edx
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx

        ; Parameters on the stack potentially require 3 dereferences if they, at origin, are uninitialized
        ; Beacause these are on the stack, 3 dereferences will be needed (1st to get to the stack, 2nd to get heap ptr, 3rd to get to data)
	        lea ebx, [ByteBuffer]
	        lea ecx, [PE_Header_StartAddress]
	    lea edx, [PE_Header_Storage]

        ;mov eax, [ebx]
        ;mov esi, [eax]

        mov eax, [ecx]
        mov esi, [eax]

        ; This causes an access violation of writing to a memory address. Apparently PE_Header_Storage doesn't need to be
        ; dereferenced a 3rd time since it's initialized with all its members as 0 (meaning storage is already set aside)
        mov eax, [edx]
        ;mov edi, [eax]
        mov edi, eax
        ;mov edi, edx

        ;add esi, 4			;Skip the PE0x000x00 bytes
        ;add edi, 4          ;Skip storing the Magic Header

        lodsd
		stosd       ;mMagic                     <---- What?! Shouldn't the Magic Header be being skipped?

		lodsw
		stosw       ;mMachine
		
		lodsw
		stosw       ;mNumberOfSections

        lodsd
        stosd       ;mTimeDateStamp

        lodsd
        stosd       ;mPointerToSymbolTable

        lodsd
        stosd       ;mNumberOfSymbols

        lodsw
        stosw       ;mSizeOfOptionalHeader

        lodsw
        stosw       ;mCharacteristics

    pop edx
    pop ecx
    pop ebx

    ret
endp

; Stores the memory address into a variable of bytes into another variable that will hold the
; addresses to those respective PE header members.
;
; Parameters: 
;   ByteBuffer              is the address of the variable containing ALL of the bytes (including the MZ header) -- hence why PE_Header_StartAddress is useful
;   PE_Header_StartAddress  is the address into ByteBuffer where the PE Magic Header starts
;   PE_Header_Storage       is where the addresses of the members of the PE header will be stored.
proc Store_PE_Header_MemberAddrs 	ByteBuffer:DWORD, PE_Header_StartAddress:DWORD, PE_Header_Storage:DWORD

    push ebx
    push ecx
    push edx
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx

        ; Parameters on the stack potentially require 3 dereferences if they, at origin, are uninitialized
        ; Beacause these are on the stack, 3 dereferences will be needed (1st to get to the stack, 2nd to get heap ptr, 3rd to get to data)
	        lea ecx, [PE_Header_StartAddress]
	    lea edx, [PE_Header_Storage]

        mov eax, [ecx]		; Contents of the memory address stored in PE_Header_StartAddress's memory address
        mov esi, [eax]		; Contents of the contents of the memory address stored in PE_Header_StartAddress's memory address

        mov eax, edx		; Memory address of PE_Header_Storage
        mov edi, [eax]		; Contents of the memory address stored in PE_Header_Storage's memory address


        ;add esi, 4			;Skip the PE0x00x00 bytes
        ;add edi, 4          		;Skip storing the Magic Header


        mov [edi], esi      ;ptr to mMachine
        add esi, 2
        add edi, 4

        mov [edi], esi      ;ptr to mNumberOfSections
        add esi, 2
        add edi, 4

        mov [edi], esi      ;ptr to mTimeDateStamp
        add esi, 4
        add edi, 4

        mov [edi], esi      ;ptr to mPointerToSymbolTable
        add esi, 4
        add edi, 4

        mov [edi], esi      ;ptr to mNumberOfSymbols
        add esi, 4
        add edi, 4

        mov [edi], esi      ;ptr to mSizeOfOptionalHeader
        add esi, 2
        add edi, 4

        mov [edi], esi      ;ptr to mCharacteristics
        add esi, 2
        add edi, 4

    pop edx
    pop ecx
    pop ebx

    ret
endp









; Reads the PE Optional header bytes from an address of a variable into a variable that will hold those values.
;
; Parameters: 
;   PE_Header_StartAddress  is the address into ByteBuffer where the PE optional header starts
;   PE_Header_Storage       is where the values of the members of the PE optional header will be stored.
proc Read_PE_Header_Optional 	PE_Header_StartAddress:DWORD, PE_Header_Storage:DWORD

    push ebx                ;ebx is being used as the Optional Header storage member cursor

    push ecx
    push edx

        xor ebx, ebx

        xor ecx, ecx
        xor edx, edx

        ; Parameters on the stack potentially require 3 dereferences if they, at origin, are uninitialized
        ; Beacause these are on the stack, 3 dereferences will be needed (1st to get to the stack, 2nd to get heap ptr, 3rd to get to data)
	        lea ecx, [PE_Header_StartAddress]
	            mov eax, [ecx]
                mov esi, [eax]

	    lea edx, [PE_Header_Storage]

        ;mov eax, [ebx]
        ;mov esi, [eax]

        ; This causes an access violation of writing to a memory address. Apparently PE_Header_Storage doesn't need to be
        ; dereferenced a 3rd time since it's initialized with all its members as 0 (meaning storage is already set aside)
        ;mov eax, [edx]
        ;;mov edi, [eax]
        ;mov edi, eax

	xor eax, eax
        ;lodsw
		;stosw       ;mMagic

		;lea ecx, [PE32OptionalHeader.mMagic]
        ;mov ebx, [edx]
		;add ebx, ecx
		;mov edi, ebx
        lea ecx, [PE32OptionalHeader.mMagic]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

		movsw           ; <-- Don't use, it messes with esi (which is ALREADY adjusted by the lodsX instruction!!!)
					;
					; It also increments esi and the edi register and NEVER copies the value to the [e]ax register!!!!
					;
					; If you do use it, do not use lods[x[ or stos[x] unless you readjust the esi register by
					; how many bytes were moved!!!
					;
					; If you only use it to move data from one location to another, it is probably fine, especially
					; since it also does not copy the value to the eax register!
        ;sub esi, 2


	xor eax, eax
        ;lodsb
        ;stosb       ;mMajorLinkerVersion			db
        lea ecx, [PE32OptionalHeader.mMajorLinkerVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsb
        ;sub esi, 2

	xor eax, eax
        ;lodsb
        ;stosb       ;mMinorLinkerVersion			db
        lea ecx, [PE32OptionalHeader.mMinorLinkerVersion]        
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsb
        ;sub esi, 2

	xor eax, eax
	;	lodsd
		;stosd       ;mSizeOfCode					dd
		lea ecx, [PE32OptionalHeader.mSizeOfCode]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
        ;sub esi, 4

	xor eax, eax
        ;lodsd
        ;stosd       ;mSizeOfInitializedData		dd
        lea ecx, [PE32OptionalHeader.mSizeOfInitializedData]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
        ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mSizeOfUninitializedData	    dd
		lea ecx, [PE32OptionalHeader.mSizeOfUninitializedData]
		mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
        ;sub esi, 4

	xor eax, eax
	;    lodsd
	    ;stosd       ;mAddressOfEntryPoint		    dd
	    lea ecx, [PE32OptionalHeader.mAddressOfEntryPoint]
	    mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
        ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mBaseOfCode					dd
		lea ecx, [PE32OptionalHeader.mBaseOfCode]
		mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
        ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mBaseOfData					dd
		lea ecx, [PE32OptionalHeader.mBaseOfData]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mImageBase					    dd
		lea ecx, [PE32OptionalHeader.mImageBase]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mSectionAlignment				dd
		lea ecx, [PE32OptionalHeader.mSectionAlignment]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
        ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mFileAlignment					dd
		lea ecx, [PE32OptionalHeader.mFileAlignment]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsw
		;stosw       ;mMajorOperatingSystemVersion	dw
		lea ecx, [PE32OptionalHeader.mMajorOperatingSystemVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2

	xor eax, eax
	;	lodsw
		;stosw       ;mMinorOperatingSystemVersion	dw
		lea ecx, [PE32OptionalHeader.mMinorOperatingSystemVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2

	xor eax, eax
	;	lodsw
		;stosw       ;mMajorImageVersion			    dw
		lea ecx, [PE32OptionalHeader.mMajorImageVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2

	xor eax, eax
	;	lodsw
		;stosw       ;mMinorImageVersion			    dw
		lea ecx, [PE32OptionalHeader.mMinorImageVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2

	xor eax, eax
	;	lodsw
		;stosw       ;mMajorSubsystemVersion			dw
		lea ecx, [PE32OptionalHeader.mMajorSubsystemVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2

	xor eax, eax
	;	lodsw
		;stosw       ;mMinorSubsystemVersion			dw
		lea ecx, [PE32OptionalHeader.mMinorSubsystemVersion]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
        ;sub esi, 2

	xor eax, eax
	;	lodsd
		;stosd       ;mWin32VersionValue			    dd
		lea ecx, [PE32OptionalHeader.mWin32VersionValue]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mSizeOfImage					dd
		lea ecx, [PE32OptionalHeader.mSizeOfImage]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mSizeOfHeaders				    dd
		lea ecx, [PE32OptionalHeader.mSizeOfHeaders]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsd
		;stosd       ;mCheckSum					    dd
		lea ecx, [PE32OptionalHeader.mCheckSum]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
	;	lodsw
		;stosw       ;mSubsystem					    dw
		lea ecx, [PE32OptionalHeader.mSubsystem]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2

	xor eax, eax
	;	lodsw
		;stosw       ;mDllCharacteristics			dw
		lea ecx, [PE32OptionalHeader.mDllCharacteristics]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw
         ;sub esi, 2



        ; If the magic code for the optional PE header is 0x010B, it is PE32
        ; If the magic code for the optional PE header is 0x020B, it is PE64
        ; If the magic code for the optional PE header is 0x0107, it is ROM
        lea ecx, [ebx - PE32OptionalHeader.mDllCharacteristics]
        push esi
        push edi
            xor esi, esi
            xor edi, edi
            mov esi, ecx
            lodsw
        pop edi
        pop esi
        ;cmp eax, 010Bh
        ;je Next4PE_OptMembers_DWORD
        cmp eax, 020Bh
        je Next4PE_OptMembers_QWORD
        ;cmp eax, 0107h
        ;je Next4PE_OptMembers_ROM

        Next4PE_OptMembers_QWORD:
		xor eax, eax
		;	lodsd
			;stosd       ;mSizeOfStackReserve			dd
			lea ecx, [PE32OptionalHeader.mSizeOfStackReserve]
	        mov ebx, [edx]
			add ebx, ecx
			mov edi, ebx
			lodsd
			movsd
			mov [edi], eax
			xor eax, eax
	         ;sub esi, 4
	
		xor eax, eax
		;	lodsd
			;stosd       ;mSizeOfStackCommit			    dd
			lea ecx, [PE32OptionalHeader.mSizeOfStackCommit]
	        mov ebx, [edx]
			add ebx, ecx
			mov edi, ebx
			lodsd
			movsd
			mov [edi], eax
			xor eax, eax
	         ;sub esi, 4
	
		xor eax, eax
		;	lodsd
			;stosd       ;mSizeOfHeapReserve			    dd
			lea ecx, [PE32OptionalHeader.mSizeOfHeapReserve]
	        mov ebx, [edx]
			add ebx, ecx
			mov edi, ebx
			lodsd
			movsd
			mov [edi], eax
			xor eax, eax
	         ;sub esi, 4

		xor eax, eax
		;	lodsd
			;stosd       ;mSizeOfHeapCommit			    dd
			lea ecx, [PE32OptionalHeader.mSizeOfHeapCommit]
	        mov ebx, [edx]
			add ebx, ecx
			mov edi, ebx
			lodsd
			movsd
			mov [edi], eax
			xor eax, eax
	         ;sub esi, 4




	; There appears to be 4 dwords worth of bytes that PEBrowse does not show but instead "skips". This is confirmed
	; when watching the esi register and looking at the bytes that are left to read in when compared to the values PEBrowse
	; shows...

	; PEBrowse is wrong! Looking at the values of the last 2 entries in the optional header, they wind up also being listed
	; as values for the 2nd section directory. Obviously this makes no sense. Using FileAlyzer by Safer-Networking (makers
	; of SpyBot Search & Destroy), this routine seems to be parsing just fine!

	xor eax, eax
	;	lodsd
		;stosd       ;mLoaderFlags					dd
		lea ecx, [PE32OptionalHeader.mLoaderFlags]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

	xor eax, eax
         ;lodsd
        ;stosd       ;mNumberOfRvaAndSizes			dd
        lea ecx, [PE32OptionalHeader.mNumberOfRvaAndSizes]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
         ;sub esi, 4

    pop edx
    pop ecx

    ret
endp



;  As per: https://www.openrce.org/reference_library/files/reference/PE%20Format.pdf
;  every directory entry has 2 dwords (virtual address and size.  Some directory entries point to
;  a further structure. All structure declarations and layouts can be seen at the openrce link provided
;  above!

;  
; Reads the PE directory header bytes from an address of a variable into a variable that will hold those values.
;
; Parameters: 
;   PE_Header_StartAddress  is the address into ByteBuffer where the PE optional header starts
;   PE_Header_Storage       is where the values of the members of the PE optional header will be stored.
proc Read_PE_Header_Directory 	PE_Header_StartAddress:DWORD, PE_Header_Storage:DWORD
	push ebx                ;ebx is being used as the Section Header storage member cursor

	push ecx
	push edx

		xor ecx, ecx
		xor edx, edx

	; Parameters on the stack potentially require 3 dereferences if they, at origin, are uninitialized
        ; Beacause these are on the stack, 3 dereferences will be needed (1st to get to the stack, 2nd to get heap ptr, 3rd to get to data)
	        lea ecx, [PE_Header_StartAddress]
	        mov eax, [ecx]
                 mov esi, [eax]
                 ;mov ecx, [eax]
                 ;mov esi, ecx
		xor eax, eax


	; One more indirection...
		lea edx, [PE_Header_Storage]
		push ecx
			mov ecx, [edx]
			mov edx, ecx
		pop ecx



	lea ecx, [PE32DirectoryHeader.VirtualAddress]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	lea ecx, [PE32DirectoryHeader.Size]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	pop edx
	pop ecx
	pop ebx

	ret
endp




; Reads the PE section header bytes from an address of a variable into a variable that will hold those values.
;
; Parameters: 
;   PE_Header_StartAddress  is the address into ByteBuffer where the PE optional header starts
;   PE_Header_Storage       is where the values of the members of the PE optional header will be stored.
proc Read_PE_Header_Section 		PE_Header_StartAddress:DWORD, PE_Header_Storage:DWORD
push ebx                ;ebx is being used as the Section Header storage member cursor

    push ecx
    push edx

        xor ebx, ebx

        xor ecx, ecx
        xor edx, edx

        ; Parameters on the stack potentially require 3 dereferences if they, at origin, are uninitialized
        ; Beacause these are on the stack, 3 dereferences will be needed (1st to get to the stack, 2nd to get heap ptr, 3rd to get to data)
	        lea ecx, [PE_Header_StartAddress]
	        mov eax, [ecx]
                 mov esi, [eax]
            ;     mov ecx, [eax]
            ;     mov esi, ecx
		xor eax, eax

	; One more indirection...
		lea edx, [PE_Header_Storage]
		push ecx
			mov ecx, [edx]
			mov edx, ecx
		pop ecx



        lea ecx, [PE32Image_Section_Header.mName]	; Name is specified in PE standard as being 8 chars. As such, there is no need to iterate character by character checking for the zero-terminator! 
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd
		movsd


	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mVirtualSize]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mVirtualAddress]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

    ;Seems to be an issue here... data read in, winds up becoming 0x00 0xF0 0xAD 0xBA
	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mSizeOfRawData]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mPointerToRawData]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mPointerToRelocations]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mPointerToLinenumbers]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mNumberOfRelocations]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mNumberOfLinenumbers]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsw

	xor eax, eax
        lea ecx, [PE32Image_Section_Header.mCharacteristics]
        mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx
		movsd

	pop edx
	pop ecx
	pop ebx
    
	ret
endp