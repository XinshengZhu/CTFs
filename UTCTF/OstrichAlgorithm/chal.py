from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

gs = '''
b *0x4017bf
continue
set *(char *)($rbp-0x20) = 'o'
set *(char *)($rbp-0x1F) = 'i'
set *(char *)($rbp-0x1E) = 'i'
set *(char *)($rbp-0x1D) = 'a'
set *(char *)($rbp-0x1C) = 'o'
set *(char *)($rbp-0x1B) = 'i'
set *(char *)($rbp-0x1A) = 'i'
set *(char *)($rbp-0x19) = 'a'
set *(char *)($rbp-0x18) = 'o'
set *(char *)($rbp-0x17) = 'i'
set *(char *)($rbp-0x16) = 'i'
set *(char *)($rbp-0x15) = 'a'
set *(char *)($rbp-0x14) = 'o'
set *(char *)($rbp-0x13) = 'i'
set *(char *)($rbp-0x12) = 'i'
set *(char *)($rbp-0x11) = 'a'
set *(char *)($rbp-0x10) = 0
'''

p = gdb.debug('./chal', gdbscript=gs)

p.interactive()

# utflag{d686e9b8f13bef2a3078c324ceafd25d}