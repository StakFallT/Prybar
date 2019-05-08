; As per: https://board.flatassembler.net/topic.php?t=19875
; From ProMiNick's forum reply post to Jin X
;macro ¤inc [cond,flname] 	{ match lft == rgt,cond \{ match rgt,lft \\{ include flname \\} \} }
;macro inc [cond,flname] 	{ match lft == rgt,cond \{ match rgt,lft \\{ include flname \\} \} }
;macro ¤def [cond,def] 	{ match =cond,cond \{  cond equ def \} }
;macro ¤def [cond,def] 	{ match =cond,cond \{  cond equ def \} }
;macro def [cond,def] 	{ match =cond,cond \{  cond equ def \} }
;macro ¤condif [cond,def,var1, val1] 	{ match =cond,cond \{  var1 equ val1 \} }
;macro condif [cond,def,var1, val1] 	{ match =cond,cond \{  var1 equ val1 \} }

ia32				equ 0
ia64				equ 1

;ARCH			equ x86
ARCH			db	ia32
;¤def ¤ARCH, ¤x86

;Pointer_Size		db 4
Pointer_Size		equ 4
;Pointer_Size		dd 4
;Pointer_Size		dd	0

;.if ARCH == x86
;	mov [Pointer_Size], byte 4
;.elseif ARCH = x64
;	mov [Pointer_Size], byte 8
;.endif
;
;¤if ¤ARCH = = ¤x86
;def ARCH, x86
;condif ARCH x86 = =Pointer_Size, 4
;condif ARCH x64 = =Pointer_Size, 8

proc Get_Arch
	mov eax, ARCH
	ret
endp

proc Set_Arch	ARCH_Type:DWORD
	mov [ARCH], ARCH_Type
	ret
endp