import os
from pwn import *
import time

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']
prefix = "squ1rrel{"
suffix = "}"

charset = "_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

for i in range(30):
    for c in charset:
        if os.path.exists('gdb_output.txt'):
            os.remove('gdb_output.txt')

        p = gdb.debug('./camelcamelcamel', gdbscript='''
            source count_hits.gdb
        ''')
        p.sendline(prefix + c + "&" * (30 - i - 1) + suffix)
        log.info(prefix + c + "&" * (30 - i - 1) + suffix)

        time.sleep(5)

        p.close()
        
        os.system('tmux kill-pane -t 1')

        if os.path.exists('gdb_output.txt'):
            with open('gdb_output.txt', 'r') as f:
                content = f.read()
                if f"{11+i}" in content:
                    prefix += c
                    log.info(f"current prefix: {prefix}")
                    break

p.interactive()

# squ1rrel{0caml_1s_c00l_4nd_we1rd_nU8X3N}