from pwn import *

p = process('./an-offset')



str = 'vompdl`nf`234'
password = ''
for i in range(len(str)):
    password += chr(ord(str[i])-1)

p.sendline(password)

p.interactive()

# flag{c54315482531c11a76aeaa828e43807c}