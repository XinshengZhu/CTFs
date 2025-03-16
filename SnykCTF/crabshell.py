from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug("./crabshell", '''
    b *(_ZN9crabshell4main17h7cd4d1599f98a37eE+137)
    continue
''')

payload = (0x31).to_bytes(1, 'little') + (0x1f221731232d1f26).to_bytes(8, 'little') + (0x64681332).to_bytes(4, 'little') + (0x64).to_bytes(1, 'little') + (0x68).to_bytes(1, 'little') + (0x68).to_bytes(1, 'little')
print(payload)
p.sendline(payload)

p.interactive()

# flag{cc811d4486decc3379dd13688a46603f}