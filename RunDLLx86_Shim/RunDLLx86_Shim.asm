
; DLL creation example

format PE GUI 4.0 DLL
entry DllEntryPoint

;include '..\..\win32a.inc'
include 'f:\fasm\include\win32a.inc'
;include 'f:\fasm\include\win32ax.inc'

include 'F:\Fasm\Projects\RunDLLx86_Shim\Globals.inc'

include 'F:\Fasm\Projects\RunDLLx86_Shim\StrLibrary.inc'

include 'F:\Fasm\Projects\RunDLLx86_Shim\Containers\Map\StrMap.inc'

include 'F:\Fasm\Projects\RunDLLx86_Shim\File_Header.inc'
include 'F:\Fasm\Projects\RunDLLx86_Shim\File_Loader.inc'


; Includes a procedure that just runs through a bunch of the StrMap functions to demonstrate their usage and test their functionality.
include 'F:\Fasm\Projects\RunDLLx86_Shim\Containers\Map\StrMap_Tests.inc'

include 'F:\\Fasm\Projects\RunDLLx86_Shim\OS\Windows\FileSystem.inc'
;include 'F:\Fasm\Projects\RunDLLx86_Shim\OS\Windows\FileManager\File.inc'
;include 'F:\Fasm\Projects\RunDLLx86_Shim\OS\Windows\FileManager\FileManager.inc'

;-----------------------------------------------------------------------------
; Initialized data
;-----------------------------------------------------------------------------
section '.data' data readable writeable executable
align 16

    ;Payload_File    db	'c:\\windows\\system32\\cmd.exe',0
    ;Payload_File    db	'f:\\fasm\\projects\\rundllx86_shim\\cmd_x86.exe',0
    Payload_File    db	'cmd_x86.exe',0

	Test_UID		db	'Unique IDentifier',0
	Test_Path		db	'c:\\temp\\',0
	Test_Filename	db	'cmd_x86.exe',0
	;PE_Header		PEHeader


    StrMap_TestElem db  'Element value',0
    StrMap_TestIdx  db  'Index_Test',0

    StringCompare_TestA	db	'StringA',0
    StringCompare_TestB	db	'StringB',0

    StringCompare_TestC	db	'StringA',0

    StrMap_Element_StrIndex0	db	'Element0',0
    StrMap_Element_StrIndex1	db	'Element1',0


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

	FileManager_Obj	dd	?

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
local   StrMap:DWORD
;local FileManager_Obj:DWORD

    ; Test StrMap
    ;push NULL
    ;call StrMap_Create
    ;mov [StrMap], eax




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



	; Test StringCompare routine
	;	Working as of 03/06/2019 1:31PM
	;		;push StringCompare_TestB
	; 		push StringCompare_TestC
	; 		push StringCompare_TestA
	; 		call 	Is_StrEqual







    ; Test StrMap
	;    push hHeap
	;    call StrMap_Create
	;    mov [StrMap], eax

        ;push StrMap_TestElem
        ;push StrMap_TestIdx
        ;push [StrMap]
	;;call StrMap_root_Add
        ;call StrMap_Add


	; Test FileManager
		push hHeap
		call FileManager_Create
		mov [FileManager_Obj], eax

		push eax
			;push eax
			;call FileManager_Increase_FileOpen_Count
			stdcall FileManager_Increase_FileOpen_Count, eax
		pop eax

		push eax
			;push eax
			;call FileManager_Decrease_FileOpen_Count
			stdcall FileManager_Decrease_FileOpen_Count, eax
		pop eax

		;push Test_Filename
		;push Test_Path
		;push Test_UID
		;push eax
		;call FileManager_Open_File
		;stdcall FileManager_Open_File, eax, Test_UID, Test_Path, Test_Filename
		stdcall FileManager_Open_File, [FileManager_Obj], Test_UID, Test_Path, Test_Filename 


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

		;push edx
		;call Locate_PE32_Header_Offset
		stdcall Locate_PE32_Header_Offset, edx


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

            ;push edx
            ;push ecx
            ;push ebx
            ;call Store_PE_Header_MemberAddrs
		stdcall Store_PE_Header_MemberAddrs, ebx, ecx, edx
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
		
		            ;push edx
		            ;push ecx
		            ;;push ebx
		            ;call Read_PE_Header_Optional
				stdcall Read_PE_Header_Optional, ecx, edx

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
			;push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx, edx
            mov [PE_AddressLocation], esi

	    lea ecx, [PE_AddressLocation]           ; Import directory
	    lea edx, [PE_Directory_Import]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Resource directory
	    lea edx, [PE_Directory_Resource]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Exception directory
	    lea edx, [PE_Directory_Exception]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Security directory
	    lea edx, [PE_Directory_Security]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; BaseReLoc directory
	    lea edx, [PE_Directory_BaseReLoc]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Debug directory
	    lea edx, [PE_Directory_Debug]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Copyright directory
	    lea edx, [PE_Directory_Copyright]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; GlobalPTR directory
	    lea edx, [PE_Directory_GlobalPTR]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; TLS directory
	    lea edx, [PE_Directory_TLS]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Load_Config directory
	    lea edx, [PE_Directory_Load_Config]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Bound_Import directory
	    lea edx, [PE_Directory_Bound_Import]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; IAT directory
	    lea edx, [PE_Directory_IAT]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Delay_Import directory
	    lea edx, [PE_Directory_Delay_Import]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
            mov [PE_AddressLocation], esi

        lea ecx, [PE_AddressLocation]           ; Com_Descriptor directory
	    lea edx, [PE_Directory_Com_Descriptor]
	        push edx
			;push ecx
			;call Read_PE_Header_Directory
			stdcall Read_PE_Header_Directory, ecx
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

    ; 7. Start filling out the IMAGE_EXPORT_DIRECTORY           structure pointed to by the PE_Directory_Export Directory       Table Entry

    ; 8. Start filling out the IMAGE_IMPORT_DESCRIPTOR          structure pointed to by the PE_Directory_Import Directory       Table Entry
    ;   Typical import Directory contains a structure similiar to this:
    ;       From IDA Pro
    ;           HEADER:4AD00168                 dd rva __IMPORT_DESCRIPTOR_msvcrt   ; Virtual address
    ;           HEADER:4AD0016C                 dd 64h                              ; Size
    ;   This means the address at 0x4AD00168 contains the values (0xD0 0x27 0x02 0x00) which is an address (added to the
    ;       base address -- in this case 0x4AD00000) that contains a structure similiar to this:
    ;           From IDA Pro
    ;               .text:4AD227D0 __IMPORT_DESCRIPTOR_msvcrt dd rva off_4AD2286C ; DATA XREF: HEADER:4AD00168o
	;				.text:4AD227D0                                         ; Import Name Table
	;				.text:4AD227D4                 dd 0FFFFFFFFh           ; Time stamp
	;				.text:4AD227D8                 dd 0FFFFFFFFh           ; Forwarder Chain
	;				.text:4AD227DC                 dd rva aMsvcrt_dll      ; DLL Name
	;				.text:4AD227E0                 dd rva exit             ; Import Address Table
	;	As per: http://www.cse.tkk.fi/fi/opinnot/T-110.6220/2010_Spring_Malware_Analysis_and_Antivirus_Tchnologies/luennot-files/Erdelyi-Reverse_engineering_2.pdf
	;		"[Each DLL has one IMAGE_IMPORT_DESCRIPTOR and consists of an Import Address Table (IAT) and a Import Name Table (INT)]
	;		The primary list is overwritten by the loader, the second one is not"

    ;   and rva off_4AD2286C contains a structure similiar to this:
    ;       From IDA Pro
    ;           .text:4AD2286C ;
	;			.text:4AD2286C ; Import names for msvcrt.dll
	;			.text:4AD2286C ;
	;			.text:4AD2286C off_4AD2286C    dd rva word_4AD22C10    ; DATA XREF: .text:__IMPORT_DESCRIPTOR_msvcrto
	;			.text:4AD22870                 dd rva word_4AD22C18
    ;           [...]
	;			.text:4AD22978                 dd rva word_4AD22F0A
	;			.text:4AD2297C                 dd 0
    ;
    ;   and rva word_4AD22C10 contains a structure similiar to this:
    ;       From IDA Pro
    ;           .text:4AD22C10 word_4AD22C10   dw 48Fh                 ; DATA XREF: .text:off_4AD2286Co
	;			.text:4AD22C12                 db 'exit',0
	;			.text:4AD22C17                 align 4
    ;   a null-terminated string essentially... This structure is an import entry for the specific dll?
    ;   48Fh should be the offset into the DLL where the function begins???
    ;
    ;   So essentially the process is this...
    ;       HEADER:4AD00168                         dd rva __IMPORT_DESCRIPTOR_msvcrt   ; Virtual address
    ;           .text:4AD2286C off_4AD2286C         dd rva word_4AD22C10                ; DATA XREF: .text:__IMPORT_DESCRIPTOR_msvcrto
    ;               .text:4AD22C10 word_4AD22C10    dw 48Fh                             ; DATA XREF: .text:off_4AD2286Co
    ;
    ;       4AD00168:   0xD0 0x27 0x02 0x00 ...         IMAGE_IMPORT_DESCRIPTOR VirtualAddress member value (Points to start of import descriptors?)
    ;       4AD227D0:   0x6C 0x28 0x02 0x00 ...             __IMPORT_DESCRIPTOR_msvcrt                      (1st import descriptor -- just happens to be for msvcrt? -- points to msvcrt's imports)
    ;       4AD2286C:   0x10 0x2C 0x02 0x00 ...                 Import names for msvcrt.dll                 (Start of msvcrt.dll's imports? First member points to ...?)
    ;       4AD22C10:   0x8F 0x04 ...                               dw 48Fh
    ;
    ;       Parse import table process:
    ;           Go to the start import descriptor table ->
    ;               Go to the import descriptor for msvcrt ->
    ;                   Go to the import entries for msvcrt.dll ->
    ;                       ...Import entry??? ->

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
	 GetProcessHeap,'GetProcessHeap',\
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
	Payload_File,'Payload_File',\
	File_Size, 'File_Size',\
	Bytes_Read, 'Bytes_Read',\
	Test_UID,'Test_UID',\
	Test_Path,'Test_Path',\
	Test_Filename,'Test_Filename',\
	FileManager_Obj,'FileManager_Obj',\
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
	StrMap_Create,'StrMap_Create',\
	StrMap_Element_Initialize,'StrMap_Element_Initialize',\
	StrMap_Add,'StrMap_Add',\
	StrMap_Initial_Set,'StrMap_Initial_Set',\
	StrMap_Add_Element,'StrMap_Add_Element',\
	StrMap_AddElement,'StrMap_AddElement',\
	StrMap_SetInitial,'StrMap_SetInitial',\
    Read_PE_Header,'Read_PE_Header',\
    Read_PE_Header_Optional,'Read_PE_Header_Optional',\
    Read_PE_Header_Directory,'Read_PE_Header_Directory',\
    Read_PE_Header_Section,'Read_PE_Header_Section',\
    Store_PE_Header_MemberAddrs,'Store_PE_Header_MemberAddrs',\
    lblRead_PE_Optional_Header,'lblRead_PE_Optional_Header',\
    lblAllocate_Directory_Entries,'lblAllocate_Directory_Entries',\
    lbl_Allocate_SectionsMemory,'lbl_Allocate_SectionsMemory',\
    StrMap_TestElem,'StrMap_TestElem',\
    StrMap_TestIdx,'StrMap_TestIdx',\
	strMap_Raw_Offset_Head,'strMap_Raw_Offset_Head',\
	strMap_Raw_Offset_Tail,'strMap_Raw_Offset_Tail',\
	strMap_Raw_Offset_Length,'strMap_Raw_Offset_Length',\
	strMap_Raw_Offset_Heap,'strMap_Raw_Offset_Heap',\
	strMap_Element_Offset_map_Raw,'strMap_Element_Offset_map_Raw',\
	strMap_Element_Offset_Head,'strMap_Element_Offset_Head',\
	strMap_Element_Offset_Name,'strMap_Element_Offset_Name',\
	strMap_Element_Offset_Element,'strMap_Element_Offset_Element',\
	strMap_Element_Offset_Tail,'strMap_Element_Offset_Tail',\
	strMap_Element_Offset_Prev,'strMap_Element_Offset_Prev',\
	strMap_Element_Offset_Next,'strMap_Element_Offset_Next',\
	strMap_Element_Offset_Length,'strMap_Element_Offset_Length',\
	StrMap_Raw_Clear,'StrMap_Raw_Clear',\
	StrMap_Raw_Get_HeadPtr,'StrMap_Raw_Get_HeadPtr',\
	StrMap_Raw_Get_Head,'StrMap_Raw_Get_Head',\
	StrMap_Raw_Get_Tail,'StrMap_Raw_Get_Tail',\
	StrMap_Raw_Get_Length,'StrMap_Raw_Get_Length',\
	StrMap_Raw_Get_Heap,'StrMap_Raw_Get_Heap',\
	StrMap_Raw_Get_TailPtr,'StrMap_Raw_Get_TailPtr',\
	StrMap_Raw_Set_Head,'StrMap_Raw_Set_Head',\
	StrMap_Raw_Set_Tail,'StrMap_Raw_Set_Tail',\
	StrMap_Raw_Set_Length,'StrMap_Raw_Set_Length',\
	StrMap_Raw_Set_Heap,'StrMap_Raw_Set_Heap',\
	StrMap_Raw_Increase_Length,'StrMap_Raw_Increase_Length',\
	StrMap_Raw_Decrease_Length,'StrMap_Raw_Decrease_Length',\
	StrMap_Element_Get_map_Raw,'StrMap_Element_Get_map_Raw',\
	StrMap_Element_Get_Head,'StrMap_Element_Get_Head',\
	StrMap_Element_Get_Name,',StrMap_Element_Get_Name',\
	StrMap_Element_Get_Element,'StrMap_Element_Get_Element',\
	StrMap_Element_Get_Tail,'StrMap_Element_Get_Tail',\
	StrMap_Element_Get_Prev,'StrMap_Element_Get_Prev',\
	StrMap_Element_Get_Next,'StrMap_Element_Get_Next',\
	StrMap_Element_Get_Length,'StrMap_Element_Get_Length',\
	StrMap_Element_Get_ByIndex,'StrMap_Element_Get_ByIndex',\
	StrMap_Element_Get,'StrMap_Element_Get',\
	Get_ElementByName_Begin,'Get_ElementByName_Begin',\
	Get_ElementByName_End,'Get_ElementByName_End',\
	StrMap_Element_Get,'StrMap_Element_Get',\
	StrMap_Element_Set_map_Raw,'StrMap_Element_Set_map_Raw',\
	StrMap_Element_Set_mapRawPtr,'StrMap_Element_Set_mapRawPtr',\
	StrMap_Element_Set_HeadPtr,'StrMap_Element_Set_HeadPtr',\
	StrMap_Element_Set_Name,',StrMap_Element_Set_Name',\
	StrMap_Element_Set_Element,'StrMap_Element_Set_Element',\
	StrMap_Element_Set_Tail,'StrMap_Element_Set_Tail',\
	StrMap_Element_Set_Prev,'StrMap_Element_Set_Prev',\
	StrMap_Element_Set_Next,'StrMap_Element_Set_Next',\
	StrMap_Element_Set_Length,'StrMap_Element_Set_Length',\
	StrMap_Element_Increase_Length, 'StrMap_Element_Increase_Length',\
	StrMap_Element_Decrease_Length, 'StrMap_Element_Decrease_Length',\
	StrMap_Element_Set_TailPtr,'StrMap_Element_Set_TailPtr',\
	FileManager_Clear,'FileManager_Clear',\
	FileManager_Create,'FileManager_Create',\
	FileManager_Create_Use_ProcHeap,'FileManager_Create_Use_ProcHeap',\
	FileManager_Create_Begin_Creation,'FileManager_Create_Begin_Creation',\
	FileManager_Open_File,'FileManager_Open_File',\
	FileManager_Get_FileOpen_Count,'FileManager_Get_FileOpen_Count',\
	FileManager_Set_FileOpen_Count,'FileManager_Set_FileOpen_Count',\
	FileManager_Increase_FileOpen_Count,'FileManager_Increase_FileOpen_Count',\
	FileManager_Decrease_FileOpen_Count,'FileManager_Decrease_FileOpen_Count',\
	FileManager_Set_Heap,'FileManager_Set_Heap',\
	File_Set_UID,'File_Set_UID',\
	File_Set_Path,'File_Set_Path',\
	File_Set_Filename,'File_Set_Filename',\
	File_Set_hFileHandle,'File_Set_hFileHandle',\
    Is_StrEqual,'Is_StrEqual'

section '.reloc' fixups data readable discardable
