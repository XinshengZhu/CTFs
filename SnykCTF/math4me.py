from pwn import *

p = process('./math4me')

ans = (0x34*2-4)/5
p.sendline(str(ans))

p.interactive()

# flag{h556cdd`=ag.c53664:45569368391gc}