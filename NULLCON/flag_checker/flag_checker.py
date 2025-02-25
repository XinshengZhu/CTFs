def reverse_sub_11e9(transformed):
    original = bytearray(len(transformed))
    
    for i in range(len(transformed)):
        # Undo bitwise rotation (right rotation by 3 bits)
        byte = ((transformed[i] >> 3) | (transformed[i] << 5)) & 0xFF

        # Undo addition of i
        byte = (byte - i) & 0xFF

        # Undo XOR with 0x5A
        original[i] = byte ^ 0x5A
    
    return original.decode('utf-8', errors='ignore')  # Use 'ignore' to avoid decode errors

# Given data_2020 from the binary
data_2020 = b'\xf8\xa8\xb8!`s\x90\x83\x80\xc3\x9b\x80\xab\tY\xd3!\xd3\xdb\xd8\xfbI\x99\xe0y<LI,)\xcc\xd4\xdcB'

# Recover the original input (password)
password = reverse_sub_11e9(data_2020)
print("Recovered password:", password)

# ENO{R3V3R53_3NG1N33R1NG_M45T3R!!!}
