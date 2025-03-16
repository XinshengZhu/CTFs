truth = 'Can birds even understand me?'
offsets = [-1, -4, 0, -1, 1, 1, 3, 2, 2, 3, 3, 8, 11, 12, 12, 13, 14, 15, 14, 16, 15, 15, 14, 17, 19, 19, 19, 19, 20, 20, 19, 25, 27, 28, 28, 26, 28, 28, 28, 28, 26, 27, 25, 27, 26, 28, 28, 27, 28, 26, 32, 31, 30, 31, 31, 30, 31, 30, 30, 29, 28, 29, 31, 28, 27, 28, 29, 29, 31, 33, 33, 32, 32, 32, 32, 32, 29, 32, 33, 32, 32, 28, 32, 30, 31, 30, 30, 31, 30, 33, 35, 33, 39, 37, 37, 37, 37, 37, 38, 39, 41, 41, 40, 39, 39, 39, 39, 39]

# Convert truth to bits
truth_bits = []
for c in truth:
    for i in range(8):
        truth_bits.append((ord(c) >> i) & 1)

# Initialize arrays
flag_size = max(offsets) + len(truth_bits)
flag_bits = [0] * flag_size
used_positions = [0] * len(truth_bits)

# Track which positions in truth have been used
offset_idx = 0
for target_pos in range(flag_size):
    for pos in range(len(truth_bits)):
        if truth_bits[pos] == 1 and used_positions[pos] == 0:
            if target_pos == pos - offsets[offset_idx]:
                flag_bits[target_pos] = 1
                used_positions[pos] = 1
                offset_idx += 1
                if offset_idx >= len(offsets):
                    break
    if offset_idx >= len(offsets):
        break

# Convert bits to bytes
flag = bytearray()
for i in range(0, len(flag_bits), 8):
    byte = 0
    for j in range(8):
        if i + j < len(flag_bits):
            byte |= flag_bits[i + j] << j
    flag.append(byte)

print(bytes(flag))

# bronco{r3v3r5ed_3n0ugh?}
