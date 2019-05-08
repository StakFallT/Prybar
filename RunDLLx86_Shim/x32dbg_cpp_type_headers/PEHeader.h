typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;

// Temporary typedef defines until these structures are implemented as their actual struct definitions
	typedef uint32_t IMAGE_IMPORT_BY_NAME;
	typedef uint32_t IMAGE_THUNK_DATA;

struct PEHeader
{
	DWORD 		*mMagic;						 // PE\0\0 or 0x00004550
	WORD 		mMachine;
	WORD 		mNumberOfSections;
	DWORD 		*mTimeDateStamp;
	DWORD 		*mPointerToSymbolTable;
	DWORD 		*mNumberOfSymbols;
	WORD 		mSizeOfOptionalHeader;
	WORD 		mCharacteristics;
};

// Contains pointers to where those members would be
struct ptrPEHeader
{
    	DWORD *ptrMagic;
    	DWORD *ptrMachine;
	DWORD *ptrNumberOfSections;
	DWORD *ptrTimeDateStamp;
	DWORD *ptrPointerToSymbolTable;
	DWORD *ptrNumberOfSymbols;
	DWORD *ptrSizeOfOptionalHeader;
	DWORD *ptrCharacteristics;
};



// Contains actual values
struct PE32OptionalHeader
{
	WORD mMagic;					 			// 0x010b - PE32, 0x020b - PE32+ (64 bit)
	BYTE mMajorLinkerVersion;
	BYTE mMinorLinkerVersion;
	DWORD *mSizeOfCode;
	DWORD *mSizeOfInitializedData;
	DWORD *mSizeOfUninitializedData;
	DWORD *mAddressOfEntryPoint;
	DWORD *mBaseOfCode;
	DWORD *mBaseOfData;
	DWORD *mImageBase;
	DWORD *mSectionAlignment;
	DWORD *mFileAlignment;
	WORD mMajorOperatingSystemVersion;
	WORD mMinorOperatingSystemVersion;
	WORD mMajorImageVersion;
	WORD mMinorImageVersion;
	WORD mMajorSubsystemVersion	;
	WORD mMinorSubsystemVersion;
	DWORD *mWin32VersionValue;
	DWORD *mSizeOfImage;
	DWORD *mSizeOfHeaders;
	DWORD *mCheckSum;
	WORD mSubsystem;
	WORD mDllCharacteristics;
	DWORD *mSizeOfStackReserve;
	DWORD *mSizeOfStackCommit;
	DWORD *mSizeOfHeapReserve;
	DWORD *mSizeOfHeapCommit;
	DWORD *mLoaderFlags;
	DWORD *mNumberOfRvaAndSizes;
};

// Contains pointers to where those members would be
struct ptrPE32OptionalHeader
{
	DWORD *ptrMagic;							 // 0x010b - PE32, 0x020b - PE32+ (64 bit)
	DWORD *ptrMajorLinkerVersion;
	DWORD *ptrMinorLinkerVersion;
	DWORD *ptrSizeOfCode;
	DWORD *ptrSizeOfInitializedData;
	DWORD *ptrSizeOfUninitializedData;
	DWORD *ptrAddressOfEntryPoint;
	DWORD *ptrBaseOfCode;
	DWORD *ptrBaseOfData;
	DWORD *ptrImageBase;
	DWORD *ptrSectionAlignment;
	DWORD *ptrFileAlignment;
	DWORD *ptrMajorOperatingSystemVersion;
	DWORD *ptrMinorOperatingSystemVersion;
	DWORD *ptrMajorImageVersion;
	DWORD *ptrMinorImageVersion;
	DWORD *ptrMajorSubsystemVersion;
	DWORD *ptrMinorSubsystemVersion;
	DWORD *ptrWin32VersionValue;
	DWORD *ptrSizeOfImage;
	DWORD *ptrSizeOfHeaders;
	DWORD *ptrCheckSum;
	DWORD *ptrSubsystem;
	DWORD *ptrDllCharacteristics;
	DWORD *ptrSizeOfStackReserve;
	DWORD *ptrSizeOfStackCommit;
	DWORD *ptrSizeOfHeapReserve;
	DWORD *ptrSizeOfHeapCommit;
	DWORD *ptrLoaderFlags;
	DWORD *ptrNumberOfRvaAndSizes;
};



// Contains actual values
struct PE32DirectoryHeader
{
	DWORD *VirtualAddress;
	DWORD *Size;
};


// Contains pointers to where those members would be
struct ptrPE32DirectoryEntry
{
	DWORD *ptrVirtualAddress;
	DWORD *ptrSize;
};



// Contains actual values
struct PE32Image_Section_Header
{
	BYTE mName[8];	// = {0};						    // db 	8 dup(0)
	DWORD *mVirtualSize;
	DWORD *mVirtualAddress;
	DWORD *mSizeOfRawData;
	DWORD *mPointerToRawData;
	DWORD *mPointerToRelocations;
	DWORD *mPointerToLinenumbers;
	WORD mNumberOfRelocations;
	WORD mNumberOfLinenumbers;
	DWORD *mCharacteristics;
};

// Contains pointers to where those members would be
struct ptrPE32Image_Section_Header
{
	DWORD *mName[8]; // = {0);						dd 	?	;8 dup(0)
	DWORD *mVirtualSize;
	DWORD *mVirtualAddress;
	DWORD *mSizeOfRawData;
	DWORD *mPointerToRawData;
	DWORD *mPointerToRelocations;
	DWORD *mPointerToLinenumbers;
	DWORD *mNumberOfRelocations;
	DWORD *mNumberOfLinenumbers;
	DWORD *mCharacteristics;
};

struct IMAGE_IMPORT_BY_NAME
{
	WORD Hint;
	BYTE Name;
};

struct IMAGE_THUNK_DATA
{
	DWORD *ForwarderString;						// LPBYTE
	DWORD *Function;
	DWORD *Ordinal;
	IMAGE_IMPORT_BY_NAME	*AddressOfData;
};

struct ptrPE32Image_Import_Descriptor
{
	// union
		DWORD *Characteristics;
	//	IMAGE_THUNK_DATA *OriginalFirstThunk;			 // RVA to original unbound IAT -- points to the Import Name Table
	// ends
	DWORD *TimeDateStamp;
	DWORD *ForwardChain;
	DWORD *Name;
	IMAGE_THUNK_DATA *FirstThunk; 					// RVA to IAT (if bound this IAT has actual addresses) -- points to the Import Address Table
};