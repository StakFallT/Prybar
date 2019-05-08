; Contains actual values
struct IMAGE_EXPORT_DIRECTORY
	Characteristics				dd	?
	TimeDateStamp				dd	?
	MajorVersion				dw	?
	MinorVersion				dw	?
	Name					dd	?
	Base						dd	?
	NumberOfFunctions			dd	?
	NumberOfNames			dd	?	; Array of DWORDs   		name_ordinal[0], name_ordinal[1], etc...
	AddressOfFunctions			dd	?	; Indexed by Ordinals	address_of_function[0], address_of_function[1], etc...		--> Code/Data
	AddressOfNames			dd	?	; Pointer to strings 		address_of_name[0], address_of_name[1], etc...
	AddressOfNameOrdinals		dd	?
ends


; Reads the PE IMAGE_EXPORT_DIRECTORY bytes from an address of a variable into a variable that will hold those values.
;
; Parameters: 
;   PE_Export_Directory_StartAddress  	is the address into ByteBuffer where the PE IMAGE_EXPORT_DIRECTORY starts
;   PE_Export_Directory_Storage       		is where the values of the members of the PE IMAGE_EXPORT_DIRECTORY will be stored.
proc Read_PE_Export_Directory 		PE_Export_Directory_StartAddress:DWORD, PE_Export_Directory_Storage:DWORD

	push ebx                ;ebx is being used as a temporary variable for determining how many bytes to bump edi each read operation

	push ecx
	push edx
	
	   xor ebx, ebx
	
	    xor ecx, ecx
	    xor edx, edx


			lea ecx, [PE_Export_Directory_StartAddress]
         	mov eax, [ecx]
     		mov esi, [eax]

			lea edx, [PE_Export_Directory_Storage]		; edx stays put this entire function since it's address serves as a starting point to determine how far in to write data to
         	mov ebx, [edx]
         	mov edx, ebx
         	mov edi, [ebx]


	lea ebx, [IMAGE_EXPORT_DIRECTORY.Characteristics]
	add edi, ebx

	movsd
	xor eax, eax

	lea ecx, [IMAGE_EXPORT_DIRECTORY.TimeDateStamp]
	mov ebx, [edx]									; REMEMBER:  edx stays put this entire function since it's address serves as a starting point to determine how far in to write data to
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.MajorVersion]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsw

	lea ecx, [IMAGE_EXPORT_DIRECTORY.MinorVersion]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsw

	lea ecx, [IMAGE_EXPORT_DIRECTORY.Name]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.Base]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.NumberOfFunctions]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.NumberOfNames]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.AddressOfNames]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	lea ecx, [IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
	mov ebx, [edx]
		add ebx, ecx
		mov edi, ebx

	movsd

	;Characteristics				dd	?
	;TimeDateStamp			dd	?
	;MajorVersion				dw	?
	;MinorVersion				dw	?
	;Name					dd	?
	;Base					dd	?
	;NumberOfFunctions			dd	?
	;NumberOfNames			dd	?	; Array of DWORDs   		name_ordinal[0], name_ordinal[1], etc...
	;AddressOfFunctions			dd	?	; Indexed by Ordinals	address_of_function[0], address_of_function[1], etc...		--> Code/Data
	;AddressOfNames			dd	?	; Pointer to strings 		address_of_name[0], address_of_name[1], etc...
	;AddressOfNameOrdinals		dd	?

	pop edx
	pop ecx
	pop ebx

	ret

endp