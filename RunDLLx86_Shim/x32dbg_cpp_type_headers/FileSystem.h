struct File
{
	DWORD	*UID;
	DWORD	*Path;
	DWORD	*Filename;
	DWORD	*hFileHandle;
};

struct FileManager
{
	StrMap_Element	*Files;
	DWORD			FilesOpen_Count;
	DWORD			Heap;
};