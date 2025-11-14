# 2025

## Pwn Challenges

### 1753CTF
| Challenge | Key Technique |
|---------------|---------------|
| [Leakcan](./1753CTF/Leakcan/) | Stack Canary Leak followed by Return Address Overwrite |

### b01lersCTF
| Challenge | Key Technique |
|---------------|---------------|
| [Gadget_Freak](./b01lersCTF/Gadget_Freak/) | Ingenious Gadgets for Stack Pivoting |
| [gueswhosstack](./b01lersCTF/gueswhosstack/) | Format String Exploit for Leak followed by [Libc GOT Hijacking](https://github.com/n132/Libc-GOT-Hijacking) |
| [scanfun](./b01lersCTF/scanfun/) | Format String Exploit with scanf for [Leak using STDOUT as Read Primitive](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive) and [FSOP](https://niftic.ca/posts/fsop/) |
| [trolley-problem](./b01lersCTF/trolley-problem/) | Stack Canary Brute-Force followed by Return Address Overwrite |
| [where](./b01lersCTF/where/) | Shellcode Injection with NX Disabled |

### BrunnerCTF
| Challenge | Key Technique |
|---------------|---------------|
| [obligatory-heap-pwn](./BrunnerCTF/obligatory-heap-pwn/) | Ingenious On-stack Data Leaks followed by Ingenious Return Address Overwrite |
| [recipe-storage](./BrunnerCTF/recipe-storage/) | [House of Enherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) followed by Tcache Poisoning for [__exit_funcs Abuse](https://blog.rop.la/en/exploiting/2024/06/11/code-exec-part1-from-exit-to-system.html) |

### BuckeyeCTF
| Challenge | Key Technique |
|---------------|---------------|
| [chirp](./BuckeyeCTF/chirp/) | Format String Exploit for Leak followed by Return Address Overwrite |
| [guessing_game](./BuckeyeCTF/guessing_game/) | Stack Canary Brute-Force followed by ROP |
| [iloverust](./BuckeyeCTF/iloverust/) | Integer Overflow for Leaks and Tcache Perthread Struct Exploit for GOT Table Overwrite |

### COMPFEST
| Challenge | Key Technique |
|---------------|---------------|
| [AllIn](./COMPFEST/AllIn/) | Format String Exploit for Leaks and [Fastbin Dup](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_dup.c) followed by [Fastbin Reverse into Tcache](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_reverse_into_tcache.c) and Tcache Poisoning for ROP |
| [gumshoe](./COMPFEST/gumshoe/) | Tcache Poisoning after Double Free for [__exit_funcs Abuse](https://blog.rop.la/en/exploiting/2024/06/11/code-exec-part1-from-exit-to-system.html) |
| [OfficeSimulator](./COMPFEST/OfficeSimulator/) | Hijack `vtable` pointer of C++ Object through Integer Overflow |

### CrewCTF
| Challenge | Key Technique |
|---------------|---------------|
| [heap-banging](./CrewCTF/heap-banging/) | Fastbin Dup into Glibc through `global_max_fast` and [Fastbin Dup into Stack](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_dup_into_stack.c) followed by Hook Overwrite through `__free_hook` |
| [heap-jail](./CrewCTF/heap-jail/) | [Large Bin Attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c) on `_IO_list_all` followed by Tcache Poisoning for [House of Apple 2](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/) |

### DawgCTF
| Challenge | Key Technique |
|---------------|---------------|
| [clobber](./DawgCTF/clobber/) | [ret2gets](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets) followed by ROP |

### GPNCTF
| Challenge | Key Technique |
|---------------|---------------|
| [nasa](./GPNCTF/nasa/) | Return Address Overwrite with AddressSanitizer on |
| [note-editor](./GPNCTF/note-editor/) | Integer Overflow followed by Buffer Overflow |

### idekCTF
| Challenge | Key Technique |
|---------------|---------------|
| [little-rop](./idekCTF/little-rop/) | ROP with Special Gadgets for Stack Pivoting to Change GOT Table Entry |
| [myspace2](./idekCTF/myspace2/) | Integer Overflow for Stack Canary Leak followed by Return Address Overwrite |

### ImaginaryCTF
| Challenge | Key Technique |
|---------------|---------------|
| [cascade](./ImaginaryCTF/cascade/) | ROP with Special Gadgets for Stack Pivoting to Change GOT Table Entry |
| [fiumicino](./ImaginaryCTF/fiumicino/) | Format String Exploit for Leaks and Environment Variable Overwrite and Return Address Overwrite |
| [multiplication](./ImaginaryCTF/multiplication/) | `malloc` to Memory-mapped Region for [Leaks using STDOUT as Read Primitive](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive) through Integer Overflow and [House of Enherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) with Tcache Perthread Struct Exploit followed by Tcache Poisoning for [FSOP](https://niftic.ca/posts/fsop/) |
| [stillerer-printf](./ImaginaryCTF/stillerer-printf/) | [Advanced Format String Exploit using Leakless Pointer Chains on Stack](https://hazyclimb.dev/posts/stiller-printf/) for Return Address LSB Overwrite |
| [twowrite](./ImaginaryCTF/twowrite/) | Two Arbitary Writes for TLS Canary Overwrite and GOT Table Overwrite |

### JerseyCTFV
| Challenge | Key Technique |
|---------------|---------------|
| [FantaxoticFledgling](./JerseyCTFV/FantaxoticFledgling/) | Replicate PRNG `srand(time(NULL))` followed by Buffer Overflow |
| [Mallorcy](./JerseyCTFV/Mallorcy/) | Format String Exploit for Leaks and GOT Table Overwrite |
| [RokosJerseyLottery](./JerseyCTFV/RokosJerseyLottery/) | `z3-solver` Utilize and Tcache Poisoning for [__exit_funcs Abuse](https://blog.rop.la/en/exploiting/2024/06/11/code-exec-part1-from-exit-to-system.html) |

### justCTF
| Challenge | Key Technique |
|---------------|---------------|
| [babyheap](./justCTF/babyheap/) | Tcache Poisoning to Heap to Fake Chunk Size for Leaks followed by Tcache Poisoning to Stack for ROP |
| [prospector](./justCTF/prospector/) | Buffer Overflow to Produce Brute-Force followed by ROP with Gadgets in LD |
| [shellcode_printer](./justCTF/shellcode_printer/) | Format String Exploit for Memory-mapped Region Overwrite |

### KashiCTF
| Challenge | Key Technique |
|---------------|---------------|
| [leap_of_faith](./KashiCTF/leap_of_faith/) | Manipulate Stack Pointer by User-controlled Jumps |
| [the_troll_zone](./KashiCTF/the_troll_zone/) | Format String Exploit for Leak followed by ROP |

### LACTF
| Challenge | Key Technique |
|---------------|---------------|
| [2password](./LACTF/2password/) | Format String Exploit for Leak |
| [gamedev](./LACTF/gamedev/) | Heap Buffer Overflow for Arbitrary Read and Write |
| [library](./LACTF/library/) | [Unsafe Unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) and [House of Enherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) followed by Tcache Poisoning for [FSOP](https://niftic.ca/posts/fsop/) |
| [minceraft](./LACTF/minceraft/) | ROP with Multiple Gadgets for Leak and Shell |
| [state-change](./LACTF/state-change/) | Stack Pivoting to `.bss` Section |

### m0leConCTF
| Challenge | Key Technique |
|---------------|---------------|
| [bronze-and-copper-pwn-shop](./m0leConCTF/bronze-and-copper-pwn-shop/) | [Fastbin Reverse into Tcache](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/fastbin_reverse_into_tcache.c) followed by Tcache Poisoning to Heap for Leaks and to Stack for ROP |
| [yet-another-heap-challenge](./m0leConCTF/yet-another-heap-challenge/) | Heap Feng Shui for Arbitrary Free by `realloc` Failure within `pthread_getattr_np`'s `pthread_attr_setaffinity` under Memory Limit (`RLIMIT_AS`) followed by Tcache Perthread Struct Exploit for FSOP |

### NahamCon
| Challenge | Key Technique |
|---------------|---------------|
| [LostMemory](./NahamCon/LostMemory/) | Tcache Poisoning to Stack for ROP |

### Nullcon
| Challenge | Key Technique |
|---------------|---------------|
| [hateful](./Nullcon/hateful/) | Format String Exploit for Leaks followed by ROP|
| [hateful2](./Nullcon/hateful2/) | Tcache Poisoning to Stack for ROP |

### PearlCTF
| Challenge | Key Technique |
|---------------|---------------|
| [mrropot](./PearlCTF/mrropot/) | Format String Exploit for Leaks followed by ROP |
| [source](./PearlCTF/source/) | Buffer Overflow to Pass `strcmp` |

### PlaidCTF
| Challenge | Key Technique |
|---------------|---------------|
| [BountyBoard](./PlaidCTF/BountyBoard/) | [RetroverFlow](https://github.com/n132/RetroverFlow/) followed by [House of Orange](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_orange.c) and Tcache Perthread Struct Exploit followed by [Leak using STDOUT as Read Primitive](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive) and [FSOP](https://niftic.ca/posts/fsop/) |

### PwnMe
| Challenge | Key Technique |
|---------------|---------------|
| [compress](./PwnMe/compress/) | [Unsafe Unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) for [__exit_funcs Abuse](https://blog.rop.la/en/exploiting/2024/06/11/code-exec-part1-from-exit-to-system.html) |
| [got](./PwnMe/got/) | Integer Overflow for GOT Table Overwrite |

### QnQSecCTF
| Challenge | Key Technique |
|---------------|---------------|
| [notez](./QnQSecCTF/notez/) | Stack Pivoting for [SROP](https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/sigreturn-oriented-programming-srop) |

### SDCTF
| Challenge | Key Technique |
|---------------|---------------|
| [Gutenberg](./SDCTF/Gutenberg/) | Format String Exploit for GOT Table Overwrite |
| [Shellphone](./SDCTF/Shellphone/) | Shellcode Injection using `execve` |

### SecurinetsCTF
| Challenge | Key Technique |
|---------------|---------------|
| [spell_manager](./SecurinetsCTF/spell_manager/) | Fastbin Poisoning to Heap and Tcache Poisoning to Glibc for Leaks and Fastbin Poisoning to Stack for ROP |
| [V-tables](./SecurinetsCTF/V-tables/) | [House of Apple 2](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/) through `_IO_2_1_stdout_`'s `_chain` |

### SekaiCTF
| Challenge | Key Technique |
|---------------|---------------|
| [learning_oop](./SekaiCTF/learning_oop/) | Ingenious Glibc Leak on Heap and Ingenious Gadgets in Glibc to Hijack `vtable` pointer of C++ Object |
| [outdated](./SekaiCTF/outdated/) | `gp` Overwrite through Integer Overflow in MIPS32 rel6 Architecture |
| [speedpwn2](./SekaiCTF/speedpwn2/) | `malloc` to Memory-mapped Region for [Leaks using STDOUT as Read Primitive](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive) through Integer Overflow followed by Tcache Poisoning for GOT Table Overwrite through Integer Overflow |

### smileyCTF
| Challenge | Key Technique |
|---------------|---------------|
| [babyrop](./smileyCTF/babyrop/) | ROP with Special Gadgets to Change `.data` Section Entry |
| [limit](./smileyCTF/limit/) | [House of Enherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) to Free in Post Tcache Poisoning Stage for Leaks and Tcache Poisoning for [FSOP](https://niftic.ca/posts/fsop/) |

### squ1rrelCTF
| Challenge | Key Technique |
|---------------|---------------|
| [jail](./squ1rrelCTF/jail/) | Stack Pivoting with `leave` Instruction Twice |
| [squ1rrel-casino](./squ1rrelCTF/squ1rrel-casino/) | Integer Overflow for GOT Table Overwrite |

### TAMUctf
| Challenge | Key Technique |
|---------------|---------------|
| [debug-1](./TAMUctf/debug-1/) | Stack Overflow followed by ROP |
| [seven](./TAMUctf/seven/) | ROP with Special Gadgets for Shellcode Injection |
| [sniper](./TAMUctf/sniper/) | Format String Exploit without Dollar Sign |

### TexSAW
| Challenge | Key Technique |
|---------------|---------------|
| [ez_printf](./TexSAW/ez_printf/) | Format String Exploit for Leaks and Return Address Overwrite |
| [ez_rop](./TexSAW/ez_rop/) | ROP with Multiple Gadgets for Leak and Shell |

### TFCCTF
| Challenge | Key Technique |
|---------------|---------------|
| [cromozominus_rex](./TFCCTF/cromozominus_rex/) | Restricted Buffer Overflow for Stack Pivoting and Return Address Overwrite in C-SKY Architecture |
| [mucusky](./TFCCTF/mucusky/) | Buffer Overflow for Stack Pivoting and Return Address Overwrite in C-SKY Architecture |

### TRXCTF
| Challenge | Key Technique |
|---------------|---------------|
| [canon_event](./TRXCTF/canon_event/) | Shellcode Injection using `fork` & `ptrace` & `wait4` |
| [virtual_insanity](./TRXCTF/virtual_insanity/) | ROP with Gadgets in `vsyscalls` Area |

### UIUCTF
| Challenge | Key Technique |
|---------------|---------------|
| [qas](./UIUCTF/qas/) | `int` to `short` Buffer Overflow |
| [doremi](./UIUCTF/doremi/) | Tcache-posioning-like Attack within [mimalloc](https://github.com/microsoft/mimalloc) Allocator |

### UMDCTF
| Challenge | Key Technique |
|---------------|---------------|
| [aura](./UMDCTF/aura/) | File Structure Arbitrary Write |
| [gambling2](./UMDCTF/gambling2/) | Return Address Overwrite within Intel 80386 Architecture |
| [one-write](./UMDCTF/one-write/) | Free in Post Tcache Poisoning Stage for Leaks followed by [Unsafe Unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) for GOT Table Overwrite |
| [prison-realm](./UMDCTF/prison-realm/) | ROP with `fgets` and Special Gadgets to Change GOT Table Entry |
| [unfinished](./UMDCTF/unfinished/) | `.bss` Section Overflow |

### UTCTF
| Challenge | Key Technique |
|---------------|---------------|
| [RETirementPlan](./UTCTF/RETirementPlan/) | Format String Exploit for Leak followed by ROP |
| [secbof](./UTCTF/secbof/) | ROP to `open` & `read` & `write` |

### WolvCTF
| Challenge | Key Technique |
|---------------|---------------|
| [DryWall](./WolvCTF/DryWall/) | ROP to `open` & `read` & `write` |
| [TakeNote](./WolvCTF/TakeNote/) | Format String Exploit for Leaks and GOT Table Overwrite |

### x3CTF
| Challenge | Key Technique |
|---------------|---------------|
| [pwny-heap](./x3CTF/pwny-heap/) | Tcache Poisoning for [FSOP](https://niftic.ca/posts/fsop/) |
