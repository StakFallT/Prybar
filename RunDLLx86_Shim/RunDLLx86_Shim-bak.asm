
; DLL creation example

format PE GUI 4.0 DLL
entry DllEntryPoint

;include '..\..\win32a.inc'
include 'f:\fasm\include\win32a.inc'

include 'F:\Fasm\Projects\RunDLLx86_Shim\File_Header.inc'
include 'F:\Fasm\Projects\RunDLLx86_Shim\File_Loader.inc'

include 'F:\Fasm\Projects\RunDLLx86_Shim\PE32\Directory_Entry\Export\IMAGE_EXPORT_DIRECTORY\Image_Export_Directory.inc'

;-----------------------------------------------------------------------------
; Initialized data
;-----------------------------------------------------------------------------
section '.data' data readable writeable executable
align 16

    ;Payload_File    db	'c:\\windows\\system32\\cmd.exe',0
    ;Payload_File    db	'f:\\fasm\\projects\\rundllx86_shim\\cmd_x86.exe',0
    Payload_File    db	'cmd_x86.exe',0

	;PE_Header		PEHeader

	Payload:
	    ;For 64-bit version of cmd
	        ;Payload_Buffer_2    rb  345089      ;~345 K bytes (1 additional for zero-terminator)
	    ;For 32-bit version of cmd
	        Payload_Buffer_2    rb  302593      ;~302 K bytes (1 additional for zero-terminator)
	        EntryPoint_Offset   dd  30362       ;0x769A bytes in is where the entry point is


;-----------------------------------------------------------------------------
; Uninitialized data
;-----------------------------------------------------------------------------
section '.bss' readable writeable executable
align 16
dd 0
;dq 0

    hFile		dd	?
    File_Size 	dd	?
    hHeap 		dd	?

	Bytes_Read		dd	?

	Payload_Buffer		dd 	?

	PE_AddressLocation	dd	?

    ; in order to be able to use the structure offsets in indirect addressing as in:
    ; mov  al, [esi+PEHeader.x]
    ;virtual at 0
    ;    PE_Header   PEHeader    ?, ?, ?, ?, ?, ?, ?, ?
    ;end virtual

    ;PE_Header   PEHeader ?, ?, ?, ?, ?, ?, ?, ?

    PE_Header               PEHeader                ; Contains actual values
    ptrPE_Header            ptrPEHeader             ; Contains pointers to where those members would be


    PE_Header_Optional      PE32OptionalHeader      ; Contains actual values
    ptrPE_Header_Optional   ptrPE32OptionalHeader   ; Contains pointers to where those members would be

   
   ;PE_DirectoryTableEntries_raw		PE32DirectoryTableEntries	;Contains the table of the directory table entries, one after another


    ; PE Data Directory entries -- pointed to by PE_DirectoryTableEntries_raw
    ;    PE_Directories		    dd	?	;Contains a pointer to the begining of PE_DirectoryTableEntries_raw

    PE_Directory_Export                 dd  ?   ;Contains a pointer for the Export directory storage
    PE_Directory_Import                 dd  ?   ;Contains a pointer for the Import directory storage
    PE_Directory_Resource               dd  ?   ;Contains a pointer for the Resource directory storage
    PE_Directory_Exception              dd  ?   ;Contains a pointer for the Exception directory storage
    PE_Directory_Security               dd  ?   ;Contains a pointer for the Security directory storage
    PE_Directory_BaseReLoc              dd  ?   ;Contains a pointer for the BaseReLoc directory storage
    PE_Directory_Debug                  dd  ?   ;Contains a pointer for the Debug directory storage
    PE_Directory_Copyright              dd  ?   ;Contains a pointer for the Copyright directory storage
    PE_Directory_GlobalPTR              dd  ?   ;Contains a pointer for the GlobalPTR directory storage
    PE_Directory_TLS                    dd  ?   ;Contains a pointer for the TLS directory storage
    PE_Directory_Load_Config            dd  ?   ;Contains a pointer for the Load_Config directory storage
    PE_Directory_Bound_Import           dd  ?   ;Contains a pointer for the Bound_Import directory storage
    PE_Directory_IAT                    dd  ?   ;Contains a pointer for the IAT directory storage
    PE_Directory_Delay_Import           dd  ?   ;Contains a pointer for the Delay_Import directory storage
    PE_Directory_Com_Descriptor         dd  ?   ;Contains a pointer for the Com_Descriptor directory storage

    ; TODO: [Feature]: Add a variable that has enough storage to contain the pointer of everyone of the Directory Table Entries so they can be easily iterated over if necessary
    ; ...

   PE_Sections_raw	        dd	?	;Contains the bytes of the sections, one after another
   PE_ptrSections_raw		dd	?	;Contains an array of pointers to the sections in PE_Sections_raw

   ; Actual data directories
   	Export_Directory	dd	?

section '.text' code readable writeable executable

proc DllEntryPoint hinstDLL,fdwReason,lpvReserved
    call ExecuteCode
	mov	eax, TRUE
    ret
endp

proc ExecuteCode
;local
;	PE_Header		PEHeader
;endl
;local		PE_Header	PEHeader

    ; Open the file
		push ecx
			xor ecx, ecx
			lea ecx, [Payload_File]
			invoke CreateFile, Payload_File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
			mov [hFile], eax
			;push 0
			;call ShowLastError
		pop ecx

    ; Get the file size
	    push ecx
	        xor ecx, ecx
	        lea ecx, [File_Size]
	        ;invoke GetFileSize, [hFile], ecx
	        invoke GetFileSize, [hFile], NULL
	        add eax, 1
	        mov [File_Size], eax
	        ;push 0
	        ;call ShowLastError
	    pop ecx

    ; Create the heap
	;invoke HeapCreate,HEAP_CREATE_ENABLE_EXECUTE,[File_Size],0
	    ;invoke HeapCreate, 0x00040000, [File_Size], 0
	    ;invoke HeapCreate, 0x00040000, File_Size, 0
	    invoke HeapCreate, 0x00040000, 0, 0
        mov [hHeap], eax
        ;push 0
        ;call ShowLastError

    ; Allocate memory from the heap
    ;   Flags: Generate Exceptions, and Zero Memory
        ;invoke HeapAlloc, [hHeap], 0x00000004 | 0x00000008, [File_Size]
        invoke HeapAlloc, [hHeap], NULL, [File_Size]
        mov [Payload_Buffer], eax
        ;push 0
        ;call ShowLastError

    ; Read the file into the heap
		push ecx
		    xor ecx, ecx

            ; Method 1: Read the executable's bytes into a heap with the executable flag created just for this DLL's process
			    lea ecx, [Payload_Buffer]
			    push edx
			        xor edx, edx
			        mov edx, [ecx]
	                invoke ReadFile, [hFile], edx, [File_Size], Bytes_Read, NULL
	            pop edx

            ; Method 2: Read the executable's bytes into a staticly sized variable in a section with the executable flag
	            ;sub [File_Size], 1
	            ;mov ecx, Payload_Buffer_2
	            ;invoke ReadFile, [hFile], ecx, [File_Size], Bytes_Read, NULL
            
		pop ecx
		;push 0
		;call ShowLastError

    ; Close the handle to the original file
	    invoke CloseHandle, [hFile]
	    ;push 0
	    ;call ShowLastError

    ; Now jump to the buffer for fun and profit; YAY!
	    ;jmp Payload
	    push ecx
	    	xor ecx, ecx

	        ; Use label as the address to jump to
		        ;lea ecx, [Payload_Buffer]
		    
		    	;jmp ecx
		    	;jmp [Payload]
		    	;lea ecx, [Payload]
	
	        ; Method 1: Use the heap memory requested from the personally created heap, for this DLL, as the address to jump to
		    	lea ecx, [Payload_Buffer]
		    	push edx
		    	    xor edx, edx
		    	    mov edx, [ecx]
		    	    ;add edx, [EntryPoint_Offset]       ; May or may not be needed.
		    	;jmp edx
		    	;pop edx
	
	        ; Method 2: Use the address of a variable, with reserved bytes of static size, as the address to jump to 
		    	;lea ecx, [Payload_Buffer_2]
		    	;add ecx, [EntryPoint_Offset]            ; May or may not be needed.
		    	;jmp ecx

		push edx
		call Locate_PE32_Header_Offset


    ; Now that the PE32 header start has been located begin reading the PE Header into the proper structures
    ; Note: the MZ (Mark ... / COFF) header has been skipped. 
    ; Read the included PE_HEADER_NOTES file for detailed information on the PE HEADER layout
	;
    ; Now that the PE32 Header's magic number (PE\0\0 or 0x00004550) offset has been found
    ; in the variable containing the file's entire set of bytes, store the address of JUST after that 4
    ; byte magic number, so that the beginning of the relevant data can always be retrieved

		push edx
		push ecx
			xor edx, edx
			xor ecx, ecx
			lea ecx, [Payload_Buffer]
			mov edx, [ecx]
			add edx, eax				; Add the number of bytes to the address -- technically, eax is the address
			                            ; of the last byte + 1 of the PE magic number, so it's not really adding anything?
		mov [PE_AddressLocation], edx
		pop ecx
		pop edx


    ; 3. Read the PE Header meta data (Machine, NumberOfSections, etc.)
    ; Store the addresses to the PE header members
        push ebx
        push ecx
        push edx
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx

            lea ebx, [Payload_Buffer]
            lea ecx, [PE_AddressLocation]
            lea edx, [ptrPE_Header]

            push edx
            push ecx
            push ebx
            call Store_PE_Header_MemberAddrs
        pop edx
        pop ecx
        pop ebx


    ; Store the values of the PE header members
        push ebx
        push ecx
        push edx
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx

            lea ebx, [Payload_Buffer]
            lea ecx, [PE_AddressLocation]
            lea edx, [PE_Header]

            push edx
            push ecx
            push ebx
            call Read_PE_Header

            ; Update the PE_AddressLocation to where esi left off
                mov [PE_AddressLocation], esi
        pop edx
        pop ecx
        pop ebx



    ; Check if there is an optional header... If there is, read in the optional header
        push ecx
            xor ecx, ecx
            lea ecx, [PE_Header.mSizeOfOptionalHeader]

            push ebx
                xor ebx, ebx
                mov ebx, [ecx]
                cmp ebx, 0
            jg lblRead_PE_Optional_Header
            ;jmp lblNo_PE_Section_Header			; Might need to be renamed
            jmp lblAllocate_Directory_Entries

            lblRead_PE_Optional_Header:
                ;   4. Read the Optional PE Header
                pop ebx				; NOTE: [BUG]: If this label is skipped because no optional header exists, the stack will
                					; become unbalanced as a pop of ebx will NOT occur to re-balance the push of ebx above!!!!

                ;push ebx
                push edx
                
	                ;xor ebx, ebx
	                xor ecx, ecx
	                xor edx, edx

                    ;lea ebx, [Payload_Buffer]
		            lea ecx, [PE_AddressLocation]
		            lea edx, [PE_Header_Optional]
		
		            push edx
		            push ecx
		            ;push ebx
		            call Read_PE_Header_Optional

		; Update the PE_AddressLocation to where esi left off
			mov [PE_AddressLocation], esi

		pop edx

   lblAllocate_Directory_Entries:
   ; TODO: [BUG]: Needs to be re-done since Each data directory is hard set (as per the PE specification?)

    ; (pre)-5. Allocate storage for Directory Entries
   	; Instead of allocating memory for each section as it's needed, allocate the amount of memory
    	; to hold all of the sections, all at once. This is possible since the number of sections is known,
    	; and the size of each section is statically set to 40 bytes (as per https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#section-table-section-headers)
	push ecx
		xor ecx, ecx

        ; For a pointer to a section of memory containing the address of each of the data directory table entries
        ; one after another...  (Presently unused however)
		    ;mov ecx, sizeof.PE32DirectoryHeader	; Should be 8, since there are two members each being a dword (2 bytes) each
		    ;imul ecx, [PE_Header_Optional.mNumberOfRvaAndSizes]
            ;invoke HeapAlloc, [hHeap], NULL, ecx
        	;	mov [PE_Directories_raw], eax
        	;	mov [PE_Directories], eax

        ; For individual data directory table entry variables...
            ; Each allocation is 8 bytes: 2 dwords (VirtualAddress, and Size)
				invoke HeapAlloc, [hHeap], NULL, 8
		        	mov [PE_Directory_Export], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Import], eax
	        	invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Resource], eax
	        	invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Exception], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Security], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_BaseReLoc], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Debug], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Copyright], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_GlobalPTR], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_TLS], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Load_Config], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Bound_Import], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_IAT], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Delay_Import], eax
                invoke HeapAlloc, [hHeap], NULL, 8
	        	    mov [PE_Directory_Com_Descriptor], eax

            ; [TODO]: [POTENTIAL_BUG]: The above allocations almost seem as though it's overallocating, because the reads just below
            ; seem to leave a set of 00 00 00 00 00 00 00 00 (8 bytes) after each variable in the same
            ; column. Use x64dbg on the reads below to see this...

	pop ecx



    ; 5. Read the data directory entries
    ;    NOTE: Remember, hard set number of data directory entries (at least I think)... should be 0x10, (16 in dec.)
		lea ecx, [PE_AddressLocation]
		;lea edx, [PE_Directories]
		;PE_DirectoryTableEntries_raw
        lea edx, [PE_Directory_Export]          ; Export directory
			push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

	    lea ecx, [PE_AddressLocation]           ; Import directory
	    lea edx, [PE_Directory_Import]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Resource directory
	    lea edx, [PE_Directory_Resource]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Exception directory
	    lea edx, [PE_Directory_Exception]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Security directory
	    lea edx, [PE_Directory_Security]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; BaseReLoc directory
	    lea edx, [PE_Directory_BaseReLoc]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Debug directory
	    lea edx, [PE_Directory_Debug]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Copyright directory
	    lea edx, [PE_Directory_Copyright]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; GlobalPTR directory
	    lea edx, [PE_Directory_GlobalPTR]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; TLS directory
	    lea edx, [PE_Directory_TLS]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Load_Config directory
	    lea edx, [PE_Directory_Load_Config]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Bound_Import directory
	    lea edx, [PE_Directory_Bound_Import]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; IAT directory
	    lea edx, [PE_Directory_IAT]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Delay_Import directory
	    lea edx, [PE_Directory_Delay_Import]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Com_Descriptor directory
	    lea edx, [PE_Directory_Com_Descriptor]
	        push edx
			push ecx
			call Read_PE_Header_Directory
            mov [PE_AddressLocation], esi

    ; 6. Read the section headers

    lbl_Allocate_SectionsMemory:
    	; Instead of allocating memory for each section as it's needed, allocate the amount of memory
    	; to hold all of the sections, all at once. This is possible since the number of sections is known,
    	; and the size of each section is statically set to 40 bytes (as per https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#section-table-section-headers)
	push ecx
		xor ecx, ecx
		;mov ecx, [PEHeader.mNumberOfSections]
		lea ecx, [PEHeader.mNumberOfSections]
        push eax
            xor eax, eax
            mov eax, sizeof.PE32Image_Section_Header
		    imul ecx, eax
		pop eax

		invoke HeapAlloc, [hHeap], NULL, ecx                    ; Seems to be 20 bytes short for some reason!
        		mov [PE_Sections_raw], eax  ; When looking at the contents of the memory address of PE_Sections_raw
        		                            ; there are roughly 0x7c bytes of 0x00, 0x7c = 124. Assuming 16 sections (which
        		                            ; there shouldn't be. 124 / 16 = 8 bytes each. Which is the same
        		                            ; as PE32DirectoryHeader !!!! This implies some sort of logic error! 
        		                            ; Check the number of rva and sizes and see if that is still being used
        		                            ; for section counts or something...
	pop ecx

    push esi
    push ebx
    push ecx
    push edx

        xor esi, esi
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx

        lea edx, [PE_Header.mNumberOfSections]
        mov bx, WORD [edx]
        xor edx, edx

        lea edx, [PE_Sections_raw]

        lblRead_Section:
            lea esi, [PE_AddressLocation]

            push edx
            push esi
            call Read_PE_Header_Section
            ; Update the PE_AddressLocation to where esi left off
			    mov [PE_AddressLocation], esi

			    ;Update the pointer into PE_Sections_raw, otherwise edx will always point to the beginning and be overwritten
			        add [edx], dword sizeof.PE32Image_Section_Header

			    add ecx, 1
			    cmp ecx, ebx
			    je lblDone_ReadingSections
			    jmp lblRead_Section

        lblDone_ReadingSections:
            pop ecx
            pop ebx
            pop esi

    ; 7. Go through each Image_Directory_Entry and parse the bytes located at that RVA
    ;	1st up is the export directory
    ;	Check virtual address
    ; For reference:
    ; 		PE_Directory_Export                 		dd  ?   ;Contains a pointer for the Export directory storage
    ; 		PE_Directory_Import                 		dd  ?   ;Contains a pointer for the Import directory storage
    ; 		PE_Directory_Resource               		dd  ?   ;Contains a pointer for the Resource directory storage
    ; 		PE_Directory_Exception              		dd  ?   ;Contains a pointer for the Exception directory storage
    ; 		PE_Directory_Security               		dd  ?   ;Contains a pointer for the Security directory storage
    ; 		PE_Directory_BaseReLoc              	dd  ?   ;Contains a pointer for the BaseReLoc directory storage
    ; 		PE_Directory_Debug                  		dd  ?   ;Contains a pointer for the Debug directory storage
    ; 		PE_Directory_Copyright              		dd  ?   ;Contains a pointer for the Copyright directory storage
    ; 		PE_Directory_GlobalPTR              	dd  ?   ;Contains a pointer for the GlobalPTR directory storage
    ; 		PE_Directory_TLS                    		dd  ?   ;Contains a pointer for the TLS directory storage
    ; 		PE_Directory_Load_Config            	dd  ?   ;Contains a pointer for the Load_Config directory storage
    ; 		PE_Directory_Bound_Import           	dd  ?   ;Contains a pointer for the Bound_Import directory storage
    ; 		PE_Directory_IAT                    		dd  ?   ;Contains a pointer for the IAT directory storage
    ; 		PE_Directory_Delay_Import           	dd  ?   ;Contains a pointer for the Delay_Import directory storage
    ; 		PE_Directory_Com_Descriptor         	dd  ?   ;Contains a pointer for the Com_Descriptor directory storage
    ;
    ; TODO: [POTENTIAL_BUG]: This code is assuming the optional header exists so as to find the Base Image Address. This may not always be the case!
    ;PE32OptionalHeader.mImageBase
    push ebx
	    push edx
	
	    	xor ebx, ebx
	    	xor edx, edx
	
	    	lea edx, [PE_Header_Optional + PE32OptionalHeader.mImageBase]
	    	mov ebx, [edx]
	    pop edx

	    push edx
	    	xor edx, edx
		lea edx, [PE_Directory_Export + PE32DirectoryHeader.VirtualAddress]
	         add ebx, edx
	    pop edx
	pop ebx


    ; 7?. The Bound Import Directory occurs next
    
    ; 8?. Start filling out the IMAGE_EXPORT_DIRECTORY           structure pointed to by the PE_Directory_Export Directory       Table Entry
    	; 	Allocate memory for Export directory storage
    		invoke HeapAlloc, [hHeap], NULL, sizeof.IMAGE_EXPORT_DIRECTORY
    		mov [Export_Directory], eax

		lea ecx, [PE_AddressLocation]           		; Export directory
	    	lea edx, [Export_Directory]
	        		push edx
			push ecx
		call Read_PE_Export_Directory
		mov [PE_AddressLocation], esi

		; TODO: [POTENTIAL_BUG]: Check to ensure there is no byte-padding for alignment. If there is, read past that and then re-adjust esi and PE_AddressLocation!!!!
		; ...
		 

    ; 8. Start filling out the IMAGE_IMPORT_DESCRIPTOR          structure pointed to by the PE_Directory_Import Directory       Table Entry

    ; 9. Start filling out the IMAGE_RESOURCE_DIRECTORY         structure pointed to by the PE_Directory_Resource Directory     Table Entry

    ; 10. Start filling out the IMAGE_DEBUG_DIRECTORY           structure pointed to by the PE_Directory_Debug Directory        Table Entry

    ; 11. Start filling out the IMAGE_TLS_DIRECTORY             structure pointed to by the PE_Directory_TLS Directory          Table Entry

    ; 12. Start filling out the IMAGE_DELAY_IMPORT_DESCRIPTOR   structure pointed to by the PE_Directory_Delay_Import Directory Table Entry



    ;mov eax,TRUE
	ret
endp

proc ShowErrorMessage hWnd,dwError
  local lpBuffer:DWORD
	lea	eax,[lpBuffer]
	invoke	FormatMessage,FORMAT_MESSAGE_ALLOCATE_BUFFER+FORMAT_MESSAGE_FROM_SYSTEM,0,[dwError],LANG_NEUTRAL,eax,0,0
	invoke	MessageBox,[hWnd],[lpBuffer],NULL,MB_ICONERROR+MB_OK
	invoke	LocalFree,[lpBuffer]
	ret
endp

proc ShowLastError hWnd
	invoke	GetLastError
	stdcall ShowErrorMessage,[hWnd],eax
	ret
endp

section '.idata' import data readable writeable

  library kernel,'KERNEL32.DLL',\
          user,'USER32.DLL'

  import kernel,\
	 GetLastError,'GetLastError',\
	 SetLastError,'SetLastError',\
	 FormatMessage,'FormatMessageA',\
	 LocalFree,'LocalFree',\
	 HeapCreate,'HeapCreate',\
	 HeapAlloc,'HeapAlloc',\
	 CreateFile,'CreateFileA',\
	 GetFileSize,'GetFileSize',\
	 ReadFile,'ReadFile',\
	 CloseHandle,'CloseHandle'

  import user,\
	 MessageBox,'MessageBoxA'

section '.edata' export data readable

  export 'RunDLLx86_Shim.DLL',\
	ShowErrorMessage,'ShowErrorMessage',\
	ShowLastError,'ShowLastError',\
	ExecuteCode,'ExecuteCode',\
	Payload,'Payload',\
	Payload_Buffer,'Payload_Buffer',\
	hHeap,'hHeap',\
	hFile, 'hFile',\
	Payload_Buffer_2, 'Payload_Buffer_2',\
	File_Size, 'File_Size',\
	Bytes_Read, 'Bytes_Read',\
	PE_Header, 'PE_Header',\
	ptrPE_Header, 'ptrPE_Header',\
	PE_Header_Optional,'PE32OptionalHeader',\
    ptrPE_Header_Optional,'ptrPE32OptionalHeader',\
   	PE_Directory_Export, 'PE_Directory_Export',\
   	PE_Directory_Import, 'PE_Directory_Import',\
   	PE_Directory_Resource, 'PE_Directory_Resource',\
   	PE_Directory_Exception, 'PE_Directory_Exception',\
   	PE_Directory_Security, 'PE_Directory_Security',\
   	PE_Directory_BaseReLoc, 'PE_Directory_BaseReLoc',\
   	PE_Directory_Debug, 'PE_Directory_Debug',\
   	PE_Directory_Copyright, 'PE_Directory_Copyright',\
   	PE_Directory_GlobalPTR, 'PE_Directory_GlobalPTR',\
   	PE_Directory_TLS, 'PE_Directory_TLS',\
   	PE_Directory_Load_Config, 'PE_Directory_Load_Config',\
   	PE_Directory_Bound_Import, 'PE_Directory_Bound_Import',\
   	PE_Directory_IAT, 'PE_Directory_IAT',\
   	PE_Directory_Delay_Import, 'PE_Directory_Delay_Import',\
   	PE_Directory_Com_Descriptor, 'PE_Directory_Com_Descriptor',\
    PE_Sections_raw,'PE_Sections_raw',\
    PE_ptrSections_raw,'PE_ptrSections_raw',\
	Locate_PE32_Header_Offset,'Locate_PE32_Header_Offset',\
	PE_Header_Start_Searching,'PE_Header_Start_Searching',\
	PE_Header_Is4thByte_00,'PE_Header_Is4thByte_00',\
	PE_Header_Is3rdByte_00,'PE_Header_Is3rdByte_00',\
	PE_Header_Is2ndByte_45,'PE_Header_Is2ndByte_45',\
	PE_Header_Is1stByte_50,'PE_Header_Is1stByte_50',\
	PE_AddressLocation,'PE_AddressLocation',\
    Read_PE_Header,'Read_PE_Header',\
    Read_PE_Header_Optional,'Read_PE_Header_Optional',\
    Read_PE_Header_Directory,'Read_PE_Header_Directory',\
    Read_PE_Header_Section,'Read_PE_Header_Section',\
    Read_PE_Export_Directory,'Read_PE_Export_Directory',\
    Store_PE_Header_MemberAddrs,'Store_PE_Header_MemberAddrs',\
    Export_Directory,'Export_Directory',\
    lblRead_PE_Optional_Header,'lblRead_PE_Optional_Header',\
    lblAllocate_Directory_Entries,'lblAllocate_Directory_Entries',\
    lbl_Allocate_SectionsMemory,'lbl_Allocate_SectionsMemory'

section '.reloc' fixups data readable discardable
