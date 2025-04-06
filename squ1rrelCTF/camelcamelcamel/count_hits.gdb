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
