# encoder.py
# Author: dipsy 
# Student Id: SLAE-1535


#!/usr/bin/python
 
simpleNot = []
simpleAdd = []
  
simpleNot.append("\x64\x77\x73\x73")
simpleAdd.append("\x63")
simpleAdd.append("\x2f")
  
encoded = ""
original = ""
  
print('Simple NOT Encoder')
  
for c in simpleNot:
        for x in bytearray(c) :
                y = ~x
  
                original += '%02x' % x
                encoded += '%02x' % (y & 0xff)
  
        print("Original: 0x{0} -> 0x{1}".format(original, encoded))
  
        # reset
        encoded = ""
        original = ""

print('Simple Add Encoder')

for c in simpleAdd:
        for x in bytearray(c) :
                y = x + 0xb0b0 #change this to the corresponding value you wish to add 
  
                original += '%02x' % x
                encoded += '%02x' % (y & 0xff)
  
        print("Original: 0x{0} -> 0x{1}".format(original, encoded))
  
        # reset
        encoded = ""
        original = ""
