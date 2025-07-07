# CTFs: always PWN, sometimes REV

**_I'm currently playing CTFs as [4n74r3s](https://ctftime.org/user/212881) with [NYUSEC](https://ctftime.org/team/439)!!!_**

## PWN Challenges

### 1753CTF
| Challenge | Key Technique |
|-----------|---------------|
| [Leakcan](./1753CTF/Leakcan/) | Stack Canary Leak followed by Stack Buffer Overflow |

### b01lersCTF
| Challenge | Key Technique |
|-----------|---------------|
| Gadget_Freak | |
| gueswhosstack | |
| scanfun | |
| trolley-problem | |
| where | |

### DawgCTF
| Challenge | Key Technique |
|-----------|---------------|
| [clobber](./DawgCTF/clobber/) | Typical [ret2gets](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets) |

### GPNCTF
| Challenge | Key Technique |
|-----------|---------------|
| [nasa](./GPNCTF/nasa/) | Return Address Overwrite with AddressSanitizer on |
| [note-editor](./GPNCTF/note-editor/) | Integer Overflow followed by Buffer Overflow|

### JerseyCTFV
| Challenge | Key Technique |
|-----------|---------------|
| FantaxoticFledgling | |
| Mallorcy | |
| RokosJerseyLottery | |

### KashiCTF
| Challenge | Key Technique |
|-----------|---------------|
| [leap_of_faith](./KashiCTF/leap_of_faith/) | Manipulate Stack Pointer by User-controlled Jumps |
| [the_troll_zone](./KashiCTF/the_troll_zone/) | Format String Exploit for Leak followed by ROP |

### LACTF
| Challenge | Key Technique |
|-----------|---------------|
| 2password | |
| gamedev | |
| library | |
| minceraft | |
| state-change | |

### NahamCon
| Challenge | Key Technique |
|-----------|---------------|
| [LostMemory](./NahamCon/LostMemory/) | Tcache Poisoning to Stack followed by ROP |

### Nullcon
| Challenge | Key Technique |
|-----------|---------------|
| [hateful](./Nullcon/hateful/) | Format String Exploit for Leaks followed by ROP|
| [hateful2](./Nullcon/hateful2/) | Tcache Poisoning to Stack followed by ROP |

### PearlCTF
| Challenge | Key Technique |
|-----------|---------------|
| [mrropot](./PearlCTF/mrropot/) | Format String Exploit for Leaks followed by ROP |
| [source](./PearlCTF/source/) | Buffer Overflow to Pass strcmp |

### PwnMe
| Challenge | Key Technique |
|-----------|---------------|
| compress | |
| got | |

### SDCTF
| Challenge | Key Technique |
|-----------|---------------|
| [Gutenberg](./SDCTF/Gutenberg/) | Format String Exploit for GOT Table Overwrite |
| [Shellphone](./SDCTF/Shellphone/) | Shellcode Injection with execve |

### smileyCTF
| Challenge | Key Technique |
|-----------|---------------|
| babyrop | |
| limit | |

### squ1rrelCTF
| Challenge | Key Technique |
|-----------|---------------|
| jail | |
| squ1rrel-casino | |

### TAMUctf
| Challenge | Key Technique |
|-----------|---------------|
| debug-1 | |
| seven | |
| sniper | |

### TexSAW
| Challenge | Key Technique |
|-----------|---------------|
| [ez_printf](./TexSAW/ez_printf/) | Format String Exploit for Leaks and Return Address Overwrite |
| [ez_rop](./TexSAW/ez_rop/) | ROP with Special Gadgets to Control Stack Pointer to Leak |

### TRXCTF
| Challenge | Key Technique |
|-----------|---------------|
| [canon_event](./TRXCTF/canon_event/) | Shellcode Injection with fork&ptrace&wait4 |
| [virtual_insanity](./TRXCTF/virtual_insanity/) | Gadgets in vsyscalls Area |

### UMDCTF
| Challenge | Key Technique |
|-----------|---------------|
| aura | |
| gambling2 | |
| one-write | |
| prison-realm | |
| unfinished | |

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
| [pwny-heap](./x3CTF/pwny-heap/) | Tcache Poisoning followed by [FSOP](https://niftic.ca/posts/fsop/) |
