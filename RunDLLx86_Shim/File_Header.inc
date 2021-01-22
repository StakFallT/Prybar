; Currently just skipped
;struct MZHeader

;ends

; Contains actual values
struct PEHeader
	mMagic				            dd	?	; // PE\0\0 or 0x00004550
	mMachine				        dw	?
	mNumberOfSections		        dw	?
	mTimeDateStamp		            dd	?
	mPointerToSymbolTable	        dd	?
	mNumberOfSymbols		        dd	?
	mSizeOfOptionalHeader	        dw	?
	mCharacteristics		        dw	?
ends

; Contains pointers to where those members would be
struct ptrPEHeader
    ptrMagic                        dd  0
    ptrMachine				        dd	0
	ptrNumberOfSections		        dd	0
	ptrTimeDateStamp		        dd	0
	ptrPointerToSymbolTable	        dd	0
	ptrNumberOfSymbols		        dd	0
	ptrSizeOfOptionalHeader	        dd	0
	ptrCharacteristics		        dd	0
ends



; Contains actual values
struct PE32OptionalHeader
	mMagic						    dw	?	; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
	mMajorLinkerVersion			    db	?
	mMinorLinkerVersion			    db	?
	mSizeOfCode					    dd	?
	mSizeOfInitializedData		    dd	?
	mSizeOfUninitializedData	    dd	?
	mAddressOfEntryPoint		    dd	?
	mBaseOfCode					    dd	?
	mBaseOfData					    dd	?
	mImageBase					    dd	?
	mSectionAlignment				dd	?
	mFileAlignment					dd	?
	mMajorOperatingSystemVersion	dw	?
	mMinorOperatingSystemVersion	dw	?
	mMajorImageVersion			    dw	?
	mMinorImageVersion			    dw	?
	mMajorSubsystemVersion			dw	?
	mMinorSubsystemVersion			dw	?
	mWin32VersionValue			    dd	?
	mSizeOfImage					dd	?
	mSizeOfHeaders				    dd	?
	mCheckSum					    dd	?
	mSubsystem					    dw	?
	mDllCharacteristics				dw	?

        ; So that this struct works for both 32-bit and 64-bit compiled executables, these next
        ; 4 members are declared as QWORDS
		mSizeOfStackReserve			    dq	?
		mSizeOfStackCommit			    dq	?
		mSizeOfHeapReserve			    dq	?
		mSizeOfHeapCommit			    dq	?

	mLoaderFlags					dd	?
	mNumberOfRvaAndSizes			dd	?
ends

; Contains pointers to where those members would be
struct ptrPE32OptionalHeader
	ptrMagic						    dd	0	; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
	ptrMajorLinkerVersion			    dd	0
	ptrMinorLinkerVersion			    dd	0
	ptrSizeOfCode					    dd	0
	ptrSizeOfInitializedData		    dd	0
	ptrSizeOfUninitializedData	        dd	0
	ptrAddressOfEntryPoint		        dd	0
	ptrBaseOfCode					    dd	0
	ptrBaseOfData					    dd	0
	ptrImageBase					    dd	0
	ptrSectionAlignment				    dd	0
	ptrFileAlignment					dd	0
	ptrMajorOperatingSystemVersion	    dd	0
	ptrMinorOperatingSystemVersion	    dd	0
	ptrMajorImageVersion			    dd	0
	ptrMinorImageVersion			    dd	0
	ptrMajorSubsystemVersion			dd	0
	ptrMinorSubsystemVersion			dd	0
	ptrWin32VersionValue			    dd	0
	ptrSizeOfImage					    dd	0
	ptrSizeOfHeaders				    dd	0
	ptrCheckSum					        dd	0
	ptrSubsystem					    dd	0
	ptrDllCharacteristics				dd	0
	ptrSizeOfStackReserve			    dd	0
	ptrSizeOfStackCommit			    dd	0
	ptrSizeOfHeapReserve			    dd	0
	ptrSizeOfHeapCommit			        dd	0
	ptrLoaderFlags					    dd	0
	ptrNumberOfRvaAndSizes			    dd	0
ends



; Contains actual values
struct PE32DirectoryHeader
	VirtualAddress 					dd	?
	Size							dd	?
ends


; Contains pointers to where those members would be
struct ptrPE32DirectoryEntry
	ptrVirtualAddress 				dd	?
	ptrSize							dd	?
ends



; Contains actual values
struct PE32Image_Section_Header
	mName						    db 	8 dup(0)
	mVirtualSize					dd 	?
	mVirtualAddress				    dd 	?
	mSizeOfRawData				    dd 	?
	mPointerToRawData				dd 	?
	mPointerToRelocations			dd	?
	mPointerToLinenumbers			dd	?
	mNumberOfRelocations			dw 	?
	mNumberOfLinenumbers			dw	?
	mCharacteristics				dd 	?
ends

; Contains pointers to where those members would be
struct ptrPE32Image_Section_Header
	mName						dd 	?	;8 dup(0)
	mVirtualSize					dd 	?
	mVirtualAddress				dd 	?
	mSizeOfRawData				dd 	?
	mPointerToRawData				dd 	?
	mPointerToRelocations			dd	?
	mPointerToLinenumbers			dd	?
	mNumberOfRelocations			dd 	?
	mNumberOfLinenumbers			dd	?
	mCharacteristics				dd 	?
ends

struct IMAGE_IMPORT_BY_NAME
	Hint							dw	?
	Name						db	0
ends

struct IMAGE_THUNK_DATA
	ForwarderString				dd					?			; LPBYTE
	Function						dd					?
	Ordinal						dd					?
	AddressOfData					IMAGE_IMPORT_BY_NAME	?
ends

struct ptrPE32Image_Import_Descriptor
	union
		Characteristics				dd					?
		OriginalFirstThunk			IMAGE_THUNK_DATA		?			; RVA to original unbound IAT -- points to the Import Name Table
	ends
	TimeDateStamp					dd					?
	ForwardChain					dd					?
	Name						dd					?
	FirstThunk						IMAGE_THUNK_DATA		?			; RVA to IAT (if bound this IAT has actual addresses) -- points to the Import Address Table
ends