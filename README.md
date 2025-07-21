# CTFs: always PWN, sometimes REV

**_I'm currently playing CTFs as [4n74r3s](https://ctftime.org/user/212881) with [NYUSEC](https://ctftime.org/team/439)!!!_**

## PWN Challenges

### 1753CTF
| Challenge | Key Technique |
|-----------|---------------|
| [Leakcan](./1753CTF/Leakcan/) | Stack Canary Leak followed by Return Address Overwrite |

### b01lersCTF
| Challenge | Key Technique |
|-----------|---------------|
| [Gadget_Freak](./b01lersCTF/Gadget_Freak/) | Ingenious Gadgets for Stack Pivot |
| [gueswhosstack](./b01lersCTF/gueswhosstack/) | Format String Exploit for Leak followed by [Libc GOT Hijacking](https://github.com/n132/Libc-GOT-Hijacking) |
| [scanfun](./b01lersCTF/scanfun/) | Format String Exploit with scanf for [Leak using STDOUT as Read Primitive](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive) and [FSOP](https://niftic.ca/posts/fsop/) |
| [trolley-problem](./b01lersCTF/trolley-problem/) | Stack Canary Brute-Force followed by Return Address Overwrite |
| [where](./b01lersCTF/where/) | Shellcode Injection with NX Disabled |

### DawgCTF
| Challenge | Key Technique |
|-----------|---------------|
| [clobber](./DawgCTF/clobber/) | [ret2gets](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets) |

### GPNCTF
| Challenge | Key Technique |
|-----------|---------------|
| [nasa](./GPNCTF/nasa/) | Return Address Overwrite with AddressSanitizer on |
| [note-editor](./GPNCTF/note-editor/) | Integer Overflow followed by Buffer Overflow |

### JerseyCTFV
| Challenge | Key Technique |
|-----------|---------------|
| [FantaxoticFledgling](./JerseyCTFV/FantaxoticFledgling/) | Replicate PRNG srand(time(NULL)) followed by Buffer Overflow |
| [Mallorcy](./JerseyCTFV/Mallorcy/) | Format String Exploit for Leaks and GOT Table Overwrite |
| [RokosJerseyLottery](./JerseyCTFV/RokosJerseyLottery/) | Z3 Solver Utilize and Tcache Poisoning for [_exit_handlers Abuse](https://ctftime.org/writeup/34804) |

### KashiCTF
| Challenge | Key Technique |
|-----------|---------------|
| [leap_of_faith](./KashiCTF/leap_of_faith/) | Manipulate Stack Pointer by User-controlled Jumps |
| [the_troll_zone](./KashiCTF/the_troll_zone/) | Format String Exploit for Leak followed by ROP |

### LACTF
| Challenge | Key Technique |
|-----------|---------------|
| [2password](./LACTF/2password/) | Format String Exploit for Leak |
| [gamedev](./LACTF/gamedev/) | Heap Buffer Overflow for Arbitrary Read and Write |
| [library](./LACTF/library/) | [Unsafe Unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) and [House of Enherjar](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_einherjar.c) followed by Tcache Poisoning for [FSOP](https://niftic.ca/posts/fsop/) |
| [minceraft](./LACTF/minceraft/) | ROP with Special Gadgets for Leak and Shell |
| [state-change](./LACTF/state-change/) | Stack Pivot to bss Section |

### NahamCon
| Challenge | Key Technique |
|-----------|---------------|
| [LostMemory](./NahamCon/LostMemory/) | Tcache Poisoning to Stack for ROP |

### Nullcon
| Challenge | Key Technique |
|-----------|---------------|
| [hateful](./Nullcon/hateful/) | Format String Exploit for Leaks followed by ROP|
| [hateful2](./Nullcon/hateful2/) | Tcache Poisoning to Stack for ROP |

### PearlCTF
| Challenge | Key Technique |
|-----------|---------------|
| [mrropot](./PearlCTF/mrropot/) | Format String Exploit for Leaks followed by ROP |
| [source](./PearlCTF/source/) | Buffer Overflow to Pass strcmp |

### PwnMe
| Challenge | Key Technique |
|-----------|---------------|
| [compress](./PwnMe/compress/) | [Unsafe Unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) for [_exit_handlers Abuse](https://ctftime.org/writeup/34804) |
| [got](./PwnMe/got/) | Integer Overflow for GOT Table Overwrite |

### SDCTF
| Challenge | Key Technique |
|-----------|---------------|
| [Gutenberg](./SDCTF/Gutenberg/) | Format String Exploit for GOT Table Overwrite |
| [Shellphone](./SDCTF/Shellphone/) | Shellcode Injection with execve |

### smileyCTF
| Challenge | Key Technique |
|-----------|---------------|
| [babyrop](./smileyCTF/babyrop/) |  |
| [limit](./smileyCTF/limit/) |  |

### squ1rrelCTF
| Challenge | Key Technique |
|-----------|---------------|
| [jail](./squ1rrelCTF/jail/) | Stack Pivot with leave/ret Instructions Twice |
| [squ1rrel-casino](./squ1rrelCTF/squ1rrel-casino/) | Integer Overflow for GOT Table Overwrite |

### TAMUctf
| Challenge | Key Technique |
|-----------|---------------|
| [debug-1](./TAMUctf/debug-1/) | Stack Overflow followed by ROP |
| [seven](./TAMUctf/seven/) | ROP with Special Gadgets for Shellcode Injection |
| [sniper](./TAMUctf/sniper/) | Format String Exploit without Dollar Sign (no_dollars) |

### TexSAW
| Challenge | Key Technique |
|-----------|---------------|
| [ez_printf](./TexSAW/ez_printf/) | Format String Exploit for Leaks and Return Address Overwrite |
| [ez_rop](./TexSAW/ez_rop/) | ROP with Special Gadgets to Control Stack Pointer to Leak |

### TRXCTF
| Challenge | Key Technique |
|-----------|---------------|
| [canon_event](./TRXCTF/canon_event/) | Shellcode Injection with fork&ptrace&wait4 |
| [virtual_insanity](./TRXCTF/virtual_insanity/) | ROP with Gadgets in vsyscalls Area |

### UMDCTF
| Challenge | Key Technique |
|-----------|---------------|
| [aura](./UMDCTF/aura/) |  |
| [gambling2](./UMDCTF/gambling2/) |  |
| [one-write](./UMDCTF/one-write/) |  |
| [prison-realm](./UMDCTF/prison-realm/) |  |
| [unfinished](./UMDCTF/unfinished/) |  |

### UTCTF
| Challenge | Key Technique |
|-----------|---------------|
| [RETirementPlan](./UTCTF/RETirementPlan/) | Format String Exploit for Leak followed by ROP |
| [secbof](./UTCTF/secbof/) | ROP to open&read&write |

### WolvCTF
| Challenge | Key Technique |
|-----------|---------------|
| [DryWall](./WolvCTF/DryWall/) | ROP to open&read&write |
| [TakeNote](./WolvCTF/TakeNote/) | Format String Exploit for Leaks and GOT Table Overwrite |

### x3CTF
| Challenge | Key Technique |
|-----------|---------------|
| [pwny-heap](./x3CTF/pwny-heap/) | Tcache Poisoning for [FSOP](https://niftic.ca/posts/fsop/) |
