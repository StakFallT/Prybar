typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;

struct FileManager
{
	StrMap_Element	*Files;
	DWORD			FilesOpen_Count;
	DWORD			Heap;
};