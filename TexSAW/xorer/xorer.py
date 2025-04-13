part1 = 0xfad195cb
part2 = 0xfa96cdd1
part3 = 0xc291c9c3

xor_key = 0xa5

# Function to convert a 32-bit integer to ASCII after XORing with key
def int_to_xored_ascii(value, key):
    result = ""
    for i in range(4):
        byte = (value >> (i * 8)) & 0xFF
        xored_byte = byte ^ key
        if 32 <= xored_byte <= 126:
            result += chr(xored_byte)
        else:
            result += f"\\x{xored_byte:02x}"
    return result

# Convert each part to ASCII after XORing with key
part1_ascii = int_to_xored_ascii(part1, xor_key)
part2_ascii = int_to_xored_ascii(part2, xor_key)
part3_ascii = int_to_xored_ascii(part3, xor_key)

# Combine all ASCII representations into a flag
flag = f"texsaw{{{part1_ascii}{part2_ascii}{part3_ascii}}}"
print(f"Flag: {flag}")

# texsaw{n0t_th3_fl4g}