typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;

// Temporary typedef defines until these structures are implemented as their actual struct definitions
	typedef uint32_t IMAGE_IMPORT_BY_NAME;
	typedef uint32_t IMAGE_THUNK_DATA;

// Contains the raw values of where the respective members in StrMap_Element point to
struct strMap_Raw
{
	DWORD rawHead; 				// Pointer to the variable that contains the address to the head 		-- this way the head can be removed and not every element needs to be updated
	DWORD rawTail; 				// Pointer to the variable that contains the address to the tail 			-- this way the tail can be removed and not every element needs to be updated
	DWORD rawLength; 			// Pointer to the variable that contains the address to the length 		-- this way elements can be added and removed without every element needing updating
	DWORD rawHeap; 				// Pointer to the heap that will be used when allocating new elements 	-- Not referenced in StrMap_Element!
};

struct StrMap_Element
{
	// Members to be treated as private:
		DWORD map_Raw;			// Essentially a private member, that holds a pointer to the raw navigation-member values

	DWORD Head	;				// Pointer to the first element

	DWORD Name; 				// Pointer to a null-terminated string that acts as the index
	DWORD Element; 				// Needs to remain a dword (pointer) since the size

	DWORD Tail; 					// Pointer to the end

	DWORD Prev; 					// Pointer to prev element
	DWORD Next; 					// Pointer to next element
 
	DWORD Length; 				// Number of elements 
};