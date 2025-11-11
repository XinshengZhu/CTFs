from pwn import *
import time
from z3 import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def clock_in():
    p.sendlineafter(b'> ', b'1')

def ask_for_raise(amount):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(amount).encode())

def quit_job():
    p.sendlineafter(b'> ', b'3')
  
# 1. clock in until all judgment conditions are met
p = process('./chal')
# p = remote('office.kctf-453514-codelab.kctf.cloud', 1337)
start_time = time.time()
while True:
    clock_in()
    response = p.recvuntil(b'Time to clock out. You made $10 today\n')
    if response.count(b'\n') == 1:
        p.recvuntil(b'Balance: $')
        balance = int(p.recvline().strip())
        log.info(f'Balance: {balance}')
        break
    if time.time() - start_time > 12:
        log.info("Running time exceeded 12 seconds, restarting...")
        p.close()
        p = process('./chal')
        # p = remote('office.kctf-453514-codelab.kctf.cloud', 1337)
        start_time = time.time()

# 2. calculate the random number using z3 solver
base = 1337
days = (balance - base) // 10
XORed = 0
for i in range(1, days):
    XORed ^= (base + i * 10) & 0xFF
random = BitVec('random', 8)
s = Solver()
result = random^(XORed&0xFF)
s.add(result & 0xa == 0)
s.add(result & 0x16 == 0)
s.add(result & 0x18 == 0)
s.add(result & 0x28 == 0)
s.add(result & -0x58 == 0)
s.add(result & 0x60 == 0)
s.add(result & 0x1 == 0)
s.check()
model = s.model()
log.info(f'random: {model[random]}')

# 3. ask for raise and quit job
ask_for_raise(model[random].as_long() * 0x101 - balance)
clock_in()
quit_job()

p.interactive()

# wctf{r4nD0m_bUt_N0t_53Cr3t_84a5}