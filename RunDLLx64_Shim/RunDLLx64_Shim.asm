
; DLL creation example

format PE64 GUI 5.0 DLL
entry DllEntryPoint
;entry start

;include 'win32a.inc'
;include 'win64a.inc'
include '..\..\include\win64wx.inc'

;-----------------------------------------------------------------------------
; Initialized data
;-----------------------------------------------------------------------------
section '.data' data readable writeable
align 16

    Payload_File    du  'c:\windows\cmd.exe',0

;-----------------------------------------------------------------------------
; Uninitialized data
;-----------------------------------------------------------------------------
section '.bss' readable writeable executable
align 16
;dq 0

    hFile           dq  ?
    File_Size       dq  ?
    Payload:
    Payload_Buffer  dq  ?


section '.text' code readable executable

;start:
proc DllEntryPoint hinstDLL,fqwReason,lpvReserved
	;mov	rax,TRUE

    ; Open the file
		;invoke CreateFile,Payload_File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL
		invoke CreateFile,Payload_File, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	    mov [hFile], rax

    ; Get the file size
        invoke GetFileSize,[hFile],File_Size

    ; Create the heap
        ;invoke HeapCreate,HEAP_CREATE_ENABLE_EXECUTE,[File_Size],0
        invoke HeapCreate,0x00040000,[File_Size],0

    ; Read the file into the heap
        invoke ReadFile,[hFile],[Payload_Buffer],[File_Size], -1, 0

    ; Close the handle to the original file
        invoke CloseHandle,[hFile]
    ; Now jump to the buffer for fun and profit; YAY!
        jmp Payload

    mov	rax,TRUE
	ret
endp

;proc Execute Executable:QWORD
;    
;    ret
;endp

; VOID ShowErrorMessage(HWND hWnd,DWORD dwError);

proc ShowErrorMessage hWnd,qwError
  local lpBuffer:QWORD
	lea	rax,[lpBuffer]
	invoke	FormatMessage,FORMAT_MESSAGE_ALLOCATE_BUFFER+FORMAT_MESSAGE_FROM_SYSTEM,0,[qwError],LANG_NEUTRAL,rax,0,0
	invoke	MessageBox,[hWnd],[lpBuffer],NULL,MB_ICONERROR+MB_OK
	invoke	LocalFree,[lpBuffer]
	ret
endp

; VOID ShowLastError(HWND hWnd);

proc ShowLastError hWnd
	invoke	GetLastError
	stdcall ShowErrorMessage,[hWnd],rax
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
	 CreateFile,'CreateFile',\
	 GetFileSize,'GetFileSize',\
	 ReadFile,'ReadFile',\
	 CloseHandle,'CloseHandle'

  import user,\
	 MessageBox,'MessageBoxA'

section '.edata' export data readable

  export 'RunDLLx64_Shim.DLL',\
	 ShowErrorMessage,'ShowErrorMessage',\
	 ShowLastError,'ShowLastError',\
	 DllEntryPoint,'DllEntryPoint'

section '.reloc' fixups data readable discardable
