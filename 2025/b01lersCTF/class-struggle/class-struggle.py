def zx_d(x):
    return x & 0xFF

def zx_q(x):
    return x & 0xFFFFFFFFFFFFFFFF

def tfkysf(arg1, arg2):
    var = arg2 & 7
    return zx_q(zx_d(arg1) >> (8 - var)) | (zx_d(arg1) << var)

def b(arg1, arg2):
    var = arg2 & 7
    return zx_q(zx_d(arg1) << (8 - var)) | (zx_d(arg1) >> var)

def jistcuazjdma(arg1, arg2):
    rax_15 = (arg2 + 3) // 7
    xor_val = ((arg2 * 0x24) & 0xFF) + (arg2 & 0xFF)
    arg1_new = arg1 ^ (xor_val & 0xFF)
    arg2_new = ((arg2 + 3) & 0xFF) - (((rax_15 << 3) & 0xFF) - (rax_15 & 0xFF))
    return zx_q(tfkysf(arg1_new, arg2_new) + 0x2a)

def recover_flag():
    target = bytes.fromhex(
        "32c0bf6c61855ce440d08fa2ef7c4a02049f371868973933bef120f14083067ef146a647fec3c867044dba109b33"
    )

    flag = []
    for i in range(len(target)):
        for c in range(0x20, 0x7f):  # Printable ASCII
            x = jistcuazjdma(c, i) ^ 0xf
            rax_11 = ((i >> 0x1f) >> 0x1d) & 0xFF  # Always 0 in 32-bit i
            shift = ((i + rax_11) & 7) - rax_11
            result = b(x, shift)
            if result & 0xFF == target[i]:
                flag.append(chr(c))
                break
        else:
            flag.append("?")
    return "".join(flag)

print("Flag:", recover_flag())

# bctf{seizing_the_m3m3s_0f_pr0ducti0n_32187ea8}