import ctypes
from pwn import *

p = remote("chall.lac.tf", 31313)

shuffled = p.recvline().decode().strip()

libc = ctypes.CDLL("libc.so.6")
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

swaps = []
length = len(shuffled)

for _ in range(22):
    round_swaps = []
    for i in range(length-1, -1, -1):
        j = libc.rand() % (i + 1)
        round_swaps.append((i, j))
    swaps.append(round_swaps)

s = list(shuffled)
for round_swaps in reversed(swaps):
    for i, j in reversed(round_swaps):
        s[i], s[j] = s[j], s[i]

log.info(''.join(s))

p.interactive()

# lactf{are_you_ready_to_learn_what_comes_next?}
