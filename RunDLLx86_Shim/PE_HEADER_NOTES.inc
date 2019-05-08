; So the layout of the PE32 (and nearly identical with the PE+ (64-bit)) header is as such:
    ;   1. The MZ (Mark ... / COFF) header stuff that we pretty much skip over (at least for now until it becomes a problem)
    ;
    ;   2. The PE magic number: PE\0\0 or 0x00004550
    ;
    ;   3. Meta data about the PE bytes
    ;       This is an IMAGE_FILE_HEADER structure
    ;       and contains:
    ;           WORD    Machine
    ;           WORD    NumberOfSections   -- Comes after the last Directory entry read in
    ;           DWORD   TimeDateStamp
    ;           DWORD   PointerToSymbolTable
    ;           DWORD   NumberOfSymbols
    ;           WORD    SizeOfOptionalHeader
    ;           WORD    Characteristics
    ;
    ;   4. The Optional PE Header           -- Can be determined to exist based on the meta data's SizeOfOptionHeader member above
    ;       This is an IMAGE_OPTIONAL_HEADER structure
    ;       and contains:
	;           WORD                    Magic
	;			BYTE                    MajorLinkerVersion
	;			BYTE                    MinorLinkerVersion
	;			DWORD                   SizeOfCode
	;			DWORD                   SizeOfInitializedData
	;			DWORD                   SizeOfUninitializedData
	;			DWORD                   AddressOfEntryPoint
	;			DWORD                   BaseOfCode
	;			DWORD                   BaseOfData
	;			DWORD                   ImageBase
	;			DWORD                   SectionAlignment
	;			DWORD                   FileAlignment
	;			WORD                    MajorOperatingSystemVersion
	;			WORD                    MinorOperatingSystemVersion
	;			WORD                    MajorImageVersion
	;			WORD                    MinorImageVersion
	;			WORD                    MajorSubsystemVersion
	;			WORD                    MinorSubsystemVersion
	;			DWORD                   Win32VersionValue
	;			DWORD                   SizeOfImage
	;			DWORD                   SizeOfHeaders
	;			DWORD                   CheckSum
	;			WORD                    Subsystem
	;			WORD                    DllCharacteristics
	;			DWORD                   SizeOfStackReserve
	;			DWORD                   SizeOfStackCommit
	;			DWORD                   SizeOfHeapReserve
	;			DWORD                   SizeOfHeapCommit
	;			DWORD                   LoaderFlags
	;			DWORD                   NumberOfRvaAndSizes
	;			_IMAGE_DATA_DIRECTORY   DataDirectory[16]
    ;
    ;   5. The data directory entries
    ;       This is an IMAGE_DIRECTORY_ENTRY_[XXXX] structure
    ;       and contains:
    ;           DWORD   VirtualAddress
    ;           DWORD   Size;
    ;
    ;       Note: There are 16 (0x10) of these hardset number of directory entries... They are
    ;       in order:
    ;           (0x01) IMAGE_DIRECTORY_ENTRY_EXPORT
    ;           (0x02) IMAGE_DIRECTORY_ENTRY_IMPORT         -> Points to an address of avariable of type IMAGE_IMPORT_DESCRIPTOR structure
    ;           (0x03) IMAGE_DIRECTORY_ENTRY_RESOURCE       -> Points to an address of avariable of type IMAGE_RESOURCE_DIRECTORY structure
    ;           (0x04) IMAGE_DIRECTORY_ENTRY_EXCEPTION
    ;           (0x05) IMAGE_DIRECTORY_ENTRY_SECURITY
    ;           (0x06) IMAGE_DIRECTORY_ENTRY_BASERELOC
    ;           (0x07) IMAGE_DIRECTORY_ENTRY_DEBUG          -> Points to an address of avariable of type IMAGE_DEBUG_DIRECTORY structure
    ;           (0x08) IMAGE_DIRECTORY_ENTRY_COPYRIGHT
    ;           (0x09) IMAGE_DIRECTORY_ENTRY_GLOBALPTR
    ;           (0x0A) IMAGE_DIRECTORY_ENTRY_TLS            -> Points to an address of avariable of type IMAGE_TLS_DIRECTORY structure
    ;           (0x0B) IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    ;           (0x0C) IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   -> VirtualAddress points to an area of memory containing of entries consisting of:
    ;                                                           a timestamp (DWORD-size),
    ;                                                           a zero-terminated string (WORD-size) of the dll name to be imported (Pointer to a pointer of a zero-terminated string???), and
    ;                                                           a member whose purpose is sort of unknown. IDA Pro says More Modules for the
    ;                                                           first one lister, and Reserved for all the others listed.  
    ;           (0x0D) IMAGE_DIRECTORY_ENTRY_IAT
    ;           (0x0E) IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   -> Points to an address of avariable of type IMAGE_DELAY_IMPORT_DESCRIPTOR structure
    ;           (0x0F) IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    ;
    ;   6. The section headers  -- The number of section headers to read in can be determined by the meta data's (IMAGE_FILE_HEADER) NumberOfSections member
    ;       Each section header is an IMAGE_SECTION_HEADER structure
    ;       and contains:
    ;           BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	;			union {
	;				DWORD PhysicalAddress
	;				DWORD VirtualSize
	;			} Misc
	;			DWORD VirtualAddress
	;			DWORD SizeOfRawData
	;			DWORD PointerToRawData
	;			DWORD PointerToRelocations
	;			DWORD PointerToLinenumbers
	;			WORD NumberOfRelocations
	;			WORD NumberOfLinenumbers
	;			DWORD Characteristics





; Useful links:
; 	http://www.rohitab.com/discuss/topic/44882-pe-loader-crashes-sometimes-why/
; 	https://jumpdollar.blogspot.com/2014/09/windbg-trying-to-find-import-address.html
;	http://www.cse.tkk.fi/fi/opinnot/T-110.6220/2010_Spring_Malware_Analysis_and_Antivirus_Tchnologies/luennot-files/Erdelyi-Reverse_engineering_2.pdf
