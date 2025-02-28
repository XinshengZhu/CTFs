from pwn import *

# Calculate input based on the equation: input = ((byte)~bVar1 ^ 0x42) - index
expected = [0x85, 0x97, 0xcd, 0x94, 0x99, 0x8c, 0xc6, 0xcb, 0xca, 0x9b, 0xc7, 0x98, 0x9e, 0x8f, 0x93, 0xcc]
result = []

# Calculate the input values based on the equation: ((byte)~bVar1 ^ 0x42) - index
for index, bVar1 in enumerate(expected):
    # ~bVar1 is the bitwise NOT of bVar1
    not_bVar1 = ~bVar1 & 0xFF  # Ensure we get a byte value (0-255)
    
    # The equation from the instructions is: input = ((byte)~bVar1 ^ 0x42) - index
    # This matches the check: (byte)~bVar1 == (byte)(input + (char)index ^ 0x42)
    input_val = (not_bVar1 ^ 0x42) - index
    
    # Ensure the result is a valid byte
    input_val &= 0xFF
    
    result.append(input_val)

print(f"Generated {len(result)} bytes for the input")

p = process("./its-go-time")

p.sendline(bytes(result))

p.interactive()

# flag{78b229bed60e12514c94e85126b43ec4}