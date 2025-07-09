import os
from pwn import *
import time

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

script_content = """
# Initialize counter
set $count = 0

# Set breakpoint at the line you want to count
# Replace 'filename.c:123' with your actual file and line number
b *('camlStdlib__List.equal_875'+84)

# Define a command to run when breakpoint is hit
commands
    set $count = $count + 1
    continue
end

# Run the program
continue

# Set up logging
set logging file gdb_output.txt
set logging enabled on

# Print the count when program exits
printf "Line was hit %d times\n", $count 

# Turn off logging
set logging enabled off
"""

with open("count_hits.gdb", "w") as f:
    f.write(script_content)

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