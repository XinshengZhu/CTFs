from pwn import *

p = process('./either-or')

def rot13(text):
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(ch)
    return "".join(result)

encoded_str = "frperg_cnffjbeq"
decoded_str = rot13(encoded_str)

p.sendline(decoded_str)

p.interactive()

# flag{f074d38932164b278a508df11b5eff89}