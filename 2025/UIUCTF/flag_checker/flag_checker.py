from sympy.ntheory import discrete_log
import struct
import sys

def parse_hex_dump(dump: str) -> list[int]:
    """Parses a string of hex bytes into a list of little-endian 32-bit integers."""
    byte_string = bytes.fromhex(dump.replace(" ", "").replace("\n", ""))
    return list(struct.unpack('<8I', byte_string))

def solve():
    """
    Solves the challenge by finding the required keys via the discrete logarithm
    and then uses them to decrypt the flag.
    """
    # The modulus M is from the constant 0xffffff2f in the binary
    MOD = 0xffffff2f

    # --- Data extracted from the memory dump ---
    test_pt_hex = "f5 b1 65 22 4a 58 b7 91 df 6a f1 d8 30 3e 61 cd c4 bb 86 c3 d1 c4 27 10 3c 34 4c 41 89 eb 2f 1e"
    test_ct_hex = "5e bf 44 dc ec 1c ff 5a c2 b4 e9 e1 92 9b 32 01 2a a9 9c 8f b4 c5 45 0e 91 4b 4a 60 59 eb 81 70"
    flag_enc_hex = "11 91 18 24 45 e9 94 fd a6 64 9f 1b a3 e9 ec 7f de 0e 2a fc f5 dc 6e 57 9c 4c e4 01 90 f7 8a 65"

    test_pt = parse_hex_dump(test_pt_hex)
    test_ct = parse_hex_dump(test_ct_hex)
    flag_enc = parse_hex_dump(flag_enc_hex)

    print(f"[+] Using modulus M = {MOD}")
    print("[+] Solving for the 8 input keys. This may take a moment... 🔑")

    input_keys = []
    # Loop to solve the discrete logarithm for each of the 8 keys
    for i in range(8):
        base = test_pt[i]
        result = test_ct[i]
        
        print(f"[*] Solving for key #{i}: pow({base}, x, {MOD}) == {result}")
        
        try:
            key = discrete_log(MOD, result, base)
            input_keys.append(key)
            print(f"[+] Found key #{i}: {key}")
        except Exception as e:
            print(f"[!] Could not solve for key #{i}: {e}")
            sys.exit(1)

    print("\n[+] Successfully found all 8 keys!")
    print(f"[+] Required program input: {input_keys}")

    # Use the found keys to decrypt the flag
    print("\n[+] Decrypting the flag... 🏴‍☠️")
    
    flag_byte_chunks = []
    for i in range(8):
        encrypted_chunk = flag_enc[i]
        key = input_keys[i]
        
        # Decrypt the 32-bit integer chunk
        decrypted_chunk = pow(encrypted_chunk, key, MOD)
        
        # --- FIX ---
        # Convert the decrypted integer into 4 bytes (little-endian order)
        # This emulates how the C program treats the integer buffer as a string.
        chunk_as_bytes = decrypted_chunk.to_bytes(4, 'little')
        flag_byte_chunks.append(chunk_as_bytes)
    
    # Join all the 4-byte chunks into a single byte string
    full_flag_bytes = b"".join(flag_byte_chunks)
    
    # A C string is terminated by a null byte ('\x00').
    # We find the first null byte and take everything before it.
    flag_content = full_flag_bytes.split(b'\x00')[0].decode('ascii')

    print("\n" + "="*50)
    print(f"✅ DECRYPTION COMPLETE. Flag: sigpwny{{{flag_content}}}")
    print("="*50)


if __name__ == "__main__":
    solve()