from Crypto.Cipher import AES
from binascii import unhexlify

def solve_ctf():
    """
    This function contains all the parameters and logic to decrypt the flag.
    """
    # 1. THE KEY
    # The initial key values from the main() function's stack.
    # var_28 = 0xe8bef2e0e0d2d6e6 (little-endian)
    # var_20 = 0xbed0e6eac4becad0 (little-endian)
    initial_key_hex = "e6d6d2e0e0f2bee8d0cabec4eae6d0be"
    
    # The 'decryptor' function performs a bitwise right shift (>> 1) on each byte.
    final_key_bytes = bytes([b >> 1 for b in unhexlify(initial_key_hex)])
    
    # 2. THE IV
    # The initial IV values from the main() function's stack.
    # var_48 = 0xdedee4c2cedcc2d6 (little-endian)
    # var_40 = 0xdededededededede (little-endian)
    # CORRECTED: The hex string is now 32 characters long (16 bytes).
    initial_iv_hex = "d6c2dccec2e4dededededededededede"

    # The 'decryptor' function also shifts each byte of the IV.
    final_iv_bytes = bytes([b >> 1 for b in unhexlify(initial_iv_hex)])

    # 3. THE CIPHERTEXT
    # This is the 96-byte (0x60) data block from 0x14000a000.
    ciphertext_hex = (
        "ae27241b7ffd2c8b3265f22ad1b063f0"
        "915b6b95dcc0eec14de2c563f7715594"
        "007d2bc75e5d614e5e51190f4ad1fd21"
        "c5c4b1ab89a4a725c5b8ed3cb3763072"
        "7b2d2ab722dc9333264725c6b5ddb00d"
        "d3c3da6313f1e2f4df5180d5f3831843"
    )
    ciphertext_bytes = unhexlify(ciphertext_hex)

    # 4. DECRYPTION
    # The binary uses AES-CBC mode.
    cipher = AES.new(final_key_bytes, AES.MODE_CBC, final_iv_bytes)
    
    # Decrypt the data
    decrypted_padded = cipher.decrypt(ciphertext_bytes)
    
    # Remove the PKCS7 padding from the decrypted data.
    # The last byte tells you how many padding bytes to remove.
    padding_length = decrypted_padded[-1]
    decrypted_unpadded = decrypted_padded[:-padding_length]

    # Print the results for verification
    print("--- CTF Solver ---")
    print(f"Final Key (Hex): {final_key_bytes.hex()}")
    print(f"Final IV (Hex):  {final_iv_bytes.hex()}")
    print("\n--- DECRYPTED FLAG ---")
    try:
        print(decrypted_unpadded.decode('utf-8'))
    except UnicodeDecodeError:
        print("Could not decode as UTF-8. Raw bytes:")
        print(decrypted_unpadded)
    print("----------------------")


if __name__ == '__main__':
    solve_ctf()

# DUCTF{There_echoes_a_chorus_enending_and_wild_Laughter_and_gossip_unruly_and_piled}