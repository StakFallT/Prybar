File_Offset_UID				dd 0
File_Offset_Path				dd (Pointer_Size * 1)
File_Offset_Filename			dd (Pointer_Size * 2)
File_Offset_hFileHandle		dd (Pointer_Size * 3)


struct File
	UID			dd			?
	Path			dd			?
	Filename		dd			?
	hFileHandle	dd			?
ends


include 'Get\File_Get.inc'
include 'Set\File_Set.inc'
;include 'Set\File_SetPtr.inc'