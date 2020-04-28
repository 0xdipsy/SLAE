# SLAE #5–3: Shell-code Analysis for linux/x86/exec
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-1535


# Background and tools 
Necessary background: C - Assembly - syscalls in linux
Used tools: Msfvenom -gcc -  ndisasm - GDB with peda extension


In this post I'm going to present my analysis for a shell-code generated from msfvenom. For starter, to display all shell-codes for linux-x86 run the following command:
``` 
dipsy@kali:~$ msfvenom -l payloads | grep linux | grep x86
``` 
I'm going to analyze the following shell-code in this post.
``` 
linux/x86/exec
``` 
Kind reminder, EAX register will hold the syscall number as well as the return value of the syscall. EBX holds the first parameter, ECX second, EDX third, ESI fourth and EDI fifth.

Generating and dissecting the shell-code
Before generating the shell-code, lets see the basic options for this payload:
``` 
dipsy@kali:~$ msfvenom -p linux/x86/exec --list-options
Options for payload/linux/x86/exec:
=========================
Name: Linux Execute Command
     Module: payload/linux/x86/exec
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal
Provided by:
    vlad902 <vlad902@gmail.com>
Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute
Description:
  Execute an arbitrary command
[...]
The shell-code executes an arbitrary command, so I set CMD option with /bin/ls. 
dipsy@kali:~$ msfvenom -p linux/x86/exec CMD=/bin/ls -f c                                                                                                                                           
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload                                                                                                                              
[-] No arch selected, selecting arch: x86 from the payload                                                                                                                                                        
No encoder or badchars specified, outputting raw payload                                                                                                                                                          
Payload size: 43 bytes                                                                                                                                                                                            
Final size of c file: 205 bytes                                                                                                                                                                                   
unsigned char buf[] =                                                                                                                                                                                             
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x6c\x73\x00\x57\x53\x89\xe1\xcd\x80";
``` 
To dissect the shell-code we can use ndisasm, where -u means operating in 32-bit mode. There is only one syscall to be analyzed in this post, 0xb. 
``` 
dipsy@ubuntu:~$ echo -ne "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x6c\x73\x00\x57\x53\x89\xe1\xcd\x80"| ndisasm -u -
00000000  6A0B              push byte +0xb
00000002  58                pop eax
00000003  99                cdq
00000004  52                push edx
00000005  66682D63          push word 0x632d
00000009  89E7              mov edi,esp
0000000B  682F736800        push dword 0x68732f
00000010  682F62696E        push dword 0x6e69622f
00000015  89E3              mov ebx,esp
00000017  52                push edx
00000018  E808000000        call dword 0x25
0000001D  2F                das
0000001E  62696E            bound ebp,[ecx+0x6e]
00000021  2F                das
00000022  6C                insb
00000023  7300              jnc 0x25
00000025  57                push edi
00000026  53                push ebx
00000027  89E1              mov ecx,esp
00000029  CD80              int 0x80
``` 

Lets prepare our skeleton to run our shell-code.
``` 
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x6c\x73\x00\x57\x53\x89\xe1\xcd\x80";
int main(){
printf("Shellcode Length:  %d\n", strlen(shellcode));
int (*ret)() = (int(*)())shellcode;
ret();
return 0;
}
``` 
Compile it:
``` 
dipsy@ubuntu:~$ gcc exec.c -o exec -z execstack -fno-stack-protector
``` 
# Analyzing SYS-CALLS (MOV AL, 0xb)
Lets start Debugging with GDB★

Running the program, setting a break-point at call EAX, which is equivalent to ret(), and run:
``` 
dipsy@ubuntu:~/Desktop/Assignments/Analysis$ sudo gdb ./exec
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
Shellcode Length:  15
``` 
The shell-code starts by setting the value of EAX to 0xb, 11 in decimal. We can identify the syscall using the following command:
``` 
dipsy@ubuntu:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 11
#define __NR_execve   11
``` 
Lets clarify what parameters need to be passed for this syscall using the manual; The prototype of the function is as follows:
``` 
int execve(const char *filename, char *const argv[], char *const envp[]);
``` 
 According to the manual, argv is an array of argument strings passed to the new program. By convention, the first of these strings should contain the filename associated with the file being executed. envp is an array of strings,
 conventionally of the form key=value, which are passed as environment
 to the new program. Both argv and envp must be terminated by a NULL
 pointer.
With that in mind, EBX will contain the file-name for the file that we wish to execute, ECX will hold the arguments to be passed to the new program, EDX will probably contain 0, since we don't have (key, value) pairs. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fc6ff4 --> 0x1a5d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211\343R\350\b")
EBP: 0xbffff748 --> 0x0 
ESP: 0xbffff70c --> 0x8048430 (<main+76>: mov    eax,0x0)
EIP: 0x804a043 --> 0x68665299
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a03e <__dso_handle+26>: add    BYTE PTR [eax],al
   0x804a040 <shellcode>: push   0xb
   0x804a042 <shellcode+2>: pop    eax
=> 0x804a043 <shellcode+3>: cdq    
   0x804a044 <shellcode+4>: push   edx
   0x804a045 <shellcode+5>: pushw  0x632d
   0x804a049 <shellcode+9>: mov    edi,esp
   0x804a04b <shellcode+11>: push   0x68732f
[------------------------------------stack-------------------------]
0000| 0xbffff70c --> 0x8048430 (<main+76>: mov    eax,0x0)
0004| 0xbffff710 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff714 --> 0xf 
0012| 0xbffff718 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff71c --> 0x8048461 (<__libc_csu_init+33>: lea    eax,[ebx-0xe0])
0020| 0xbffff720 --> 0xffffffff 
0024| 0xbffff724 --> 0xb7e54196 (add    ebx,0x172e5e)
0028| 0xbffff728 --> 0xb7fc6ff4 --> 0x1a5d7c 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a043 in shellcode ()
``` 
The next instruction to be executed is CDQ.
According to INTEL manual, The CDQ instruction extends the sign bit of AL, AX, EAX to AH,DX,EDX.

## CDQ let EDX your wing-man
Since EAX is mostly used for SYSCALLS, and most SYSCALLS don't set the flag bit in EAX, extending the sign bit comes in handy if you want to use a register as a NULL terminator for strings or if you want to use a zeroed out register, in this case EDX will be your wing-man.

Stepping through instructions, we find that EDX is pushed into the stack as a NULL terminator; Then -c is pushed into the stack and saved in EDI. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fc6ff4 --> 0x1a5d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff706 --> 0x632d ('-c')
EBP: 0xbffff748 --> 0x0 
ESP: 0xbffff706 --> 0x632d ('-c')
EIP: 0x804a04b ("h/sh")
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a044 <shellcode+4>: push   edx
   0x804a045 <shellcode+5>: pushw  0x632d
   0x804a049 <shellcode+9>: mov    edi,esp
=> 0x804a04b <shellcode+11>: push   0x68732f
   0x804a050 <shellcode+16>: push   0x6e69622f
   0x804a055 <shellcode+21>: mov    ebx,esp
   0x804a057 <shellcode+23>: push   edx
   0x804a058 <shellcode+24>: call   0x804a065 <shellcode+37>
[------------------------------------stack-------------------------]
0000| 0xbffff706 --> 0x632d ('-c')
0004| 0xbffff70a --> 0x84300000 
0008| 0xbffff70e --> 0x85100804 
0012| 0xbffff712 --> 0xf0804 
0016| 0xbffff716 --> 0x9ff40000 
0020| 0xbffff71a --> 0x84610804 
0024| 0xbffff71e --> 0xffff0804 
0028| 0xbffff722 --> 0x4196ffff 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04b in shellcode ()
``` 
After that, /bin/sh is pushed into the stack and saved to EBX register 
``` 
[----------------------------------registers-----------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6fe ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff706 --> 0x632d ('-c')
EBP: 0xbffff748 --> 0x0 
ESP: 0xbffff6fe ("/bin/sh")
EIP: 0x804a057 --> 0x8e852
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a04b <shellcode+11>: push   0x68732f
   0x804a050 <shellcode+16>: push   0x6e69622f
   0x804a055 <shellcode+21>: mov    ebx,esp
=> 0x804a057 <shellcode+23>: push   edx
   0x804a058 <shellcode+24>: call   0x804a065 <shellcode+37>
   0x804a05d <shellcode+29>: das    
   0x804a05e <shellcode+30>: bound  ebp,QWORD PTR [ecx+0x6e]
   0x804a061 <shellcode+33>: das
[------------------------------------stack-------------------------]
0000| 0xbffff6fe ("/bin/sh")
0004| 0xbffff702 --> 0x68732f ('/sh')
0008| 0xbffff706 --> 0x632d ('-c')
0012| 0xbffff70a --> 0x84300000 
0016| 0xbffff70e --> 0x85100804 
0020| 0xbffff712 --> 0xf0804 
0024| 0xbffff716 --> 0x9ff40000 
0028| 0xbffff71a --> 0x84610804 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a057 in shellcode ()
``` 
EDX is once again pushed into the stack to act as a NULL terminator, then a CALL instruction is initiated to push the program name into the stack. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6fe ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff706 --> 0x632d ('-c')
EBP: 0xbffff748 --> 0x0 
ESP: 0xbffff6f6 --> 0x804a05d ("/bin/ls")
EIP: 0x804a065 --> 0xe1895357
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a061 <shellcode+33>: das    
   0x804a062 <shellcode+34>: ins    BYTE PTR es:[edi],dx
   0x804a063 <shellcode+35>: jae    0x804a065 <shellcode+37>
=> 0x804a065 <shellcode+37>: push   edi
   0x804a066 <shellcode+38>: push   ebx
   0x804a067 <shellcode+39>: mov    ecx,esp
   0x804a069 <shellcode+41>: int    0x80
   0x804a06b <shellcode+43>: add    BYTE PTR [eax],al
[------------------------------------stack-------------------------]
0000| 0xbffff6f6 --> 0x804a05d ("/bin/ls")
0004| 0xbffff6fa --> 0x0 
0008| 0xbffff6fe ("/bin/sh")
0012| 0xbffff702 --> 0x68732f ('/sh')
0016| 0xbffff706 --> 0x632d ('-c')
0020| 0xbffff70a --> 0x84300000 
0024| 0xbffff70e --> 0x85100804 
0028| 0xbffff712 --> 0xf0804 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a065 in shellcode ()
``` 
Finally, EDI which contains -c option is pushed into the stack side-by-side to the EBX register which holds /bin/sh and then saving those in the ECX register. 
``` 
[----------------------------------registers-----------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6fe ("/bin/sh")
ECX: 0xbffff6ee --> 0xbffff6fe ("/bin/sh")
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff706 --> 0x632d ('-c')
EBP: 0xbffff748 --> 0x0 
ESP: 0xbffff6ee --> 0xbffff6fe ("/bin/sh")
EIP: 0x804a069 --> 0x80cd
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a065 <shellcode+37>: push   edi
   0x804a066 <shellcode+38>: push   ebx
   0x804a067 <shellcode+39>: mov    ecx,esp
=> 0x804a069 <shellcode+41>: int    0x80
   0x804a06b <shellcode+43>: add    BYTE PTR [eax],al
   0x804a06d: add    BYTE PTR [eax],al
   0x804a06f: add    BYTE PTR [eax],al
   0x804a071 <dtor_idx.6161+1>: add    BYTE PTR [eax],al
[------------------------------------stack-------------------------]
0000| 0xbffff6ee --> 0xbffff6fe ("/bin/sh")
0004| 0xbffff6f2 --> 0xbffff706 --> 0x632d ('-c')
0008| 0xbffff6f6 --> 0x804a05d ("/bin/ls")
0012| 0xbffff6fa --> 0x0 
0016| 0xbffff6fe ("/bin/sh")
0020| 0xbffff702 --> 0x68732f ('/sh')
0024| 0xbffff706 --> 0x632d ('-c')
0028| 0xbffff70a --> 0x84300000 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a069 in shellcode ()
```
So, ultimately, EBX is pointing to the file that we want to exeute, AKA /bin/sh. ECX holds the parameters that we want to pass to that program, AKA /bin/ls. EDX will contain 0 since we don't have (key,value) pair. 

# Effect of /bin/ls 
Stepping into the SYSCALL int 0x80 yields in listing the current files in the current directory. 
```
gdb-peda$ si
process 3291 is executing new program: /bin/dash
[New process 3405]
process 3405 is executing new program: /bin/ls
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/i386-linux-gnu/libthread_db.so.1".
1~      Reverse shell       exec
Bind shell   Shell_Bind_TCP.nasm~      exec.c
Crypter      Shell_Reverse_TCP (copy).nasm~  exec.c~
EggShell     Shell_Reverse_TCP.nasm~      peda-session-exec.txt
Encoder      bind_op.nasm~       peda-session-rm.txt
Polymorphic  bindopt.nasm~       shellcode.c~
[Inferior 2 (process 3405) exited normally]
``` 

Your questions, comments are valuable and highly appreciated. Thank you for bearing to the end!
```
XOR EAX, EAX 
MOV al, 0x1 
int 0x80
```
