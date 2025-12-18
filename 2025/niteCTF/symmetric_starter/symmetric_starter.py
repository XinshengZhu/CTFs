import sys
from z3 import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
import re

# === 1. Parse Challenge Data ===
# We read the ciphertext and the 'shifts' value from out.txt
try:
    with open("out.txt", "r") as f:
        lines = f.readlines()
        ct_hex = lines[0].strip()
        shifts_hex = lines[1].strip()
except FileNotFoundError:
    print("[-] out.txt not found. Please ensure it is in the same directory.")
    # Fallback to the data provided in the prompt if file is missing
    ct_hex = "97dd3c17644f43689603fd3ae505743ea5d8a116337267cda591c51fb89aecb9aecab0715a8f763de910c7230af1a7570f935d0f52e4e7506613624321ecd66f1eebd7f7d481ab1cfc85d5bcc42246b09f502c062e501824df89bd0aef5080108fd8370775a88c004c134ca151dcf64ab9691ffdf4bfd5e06b1f6e167620add68435041a0700b859a460d1e138d66c1a8c4789df20bced9985c5bec9078b4c2185b15d2a4c9fd7e26ede487fd4bba4fa4ff8709b8e8d9a00fcd088edc6187ded39862b8af0c55a66d0bd4553f7a75f495bee5f70b0a8dbdbdcd7966aaa3e5390c9de9575576eb9571bab74790039983c90a64afc2dc31e16b8b1a7a41fa734a8fa5bd625c86d206eb7562dae01a5d2be9421eefdde8f3b7c33f31ae09455e656e6ae0090b060d82868a2f72e2a8b53814435b7ffbafeb2182d213a677b0918f043b81190ec5572ee3903720574bb227613c60813dc9a9391e22e7cae1cc41322e8be00a1ffaec43861264d81e1aabec9b9ad92a06dacfd6ffdba2710d1439fb0945f1ab6b1d599a654bba3f7e8a0b0cf671160c26629d8dcd629ebfe5117214f29224ae5ee119ff50157d97d84f5ddd44b5c3ac6edfb726bfc721dd407f37314c6567ec5aa0486203dba822d98380cc2cd9ed833b3fc26148831010e3b1f75a3a2d4215440f462b591d26e466c4dc40b840d568f2bd8a38f05bc0663e788c60ea5af71b15a55edfa008a8bd1829131afa1294e51217f35ab60a09e2e311e02d704c6d1491ba3343b22ac3ab9d4eeff7f07229e27ab170c223aa406222990e694a40bb61993dd0d7af59463463cecc15bec8175f9b9b5829004cadee88580c4e201fb0fef9079a3b85034acf9645afdf41a9d389eeb2458ecc563c08f2ab97a4d1cf9e4b29046c937dff5321e0e4ba914f635e8cb0bb93a58fbad6eec4dff029c614655488914b7086c79834c14c894d129df24d6323f5f6307cbc59efe11553b98182396e1b965107ed632eb44350c0b4eeec69e184a9ae5160c94928793b59f31f98c224890acf60833ffa0efe4f17f3fb6a479ff038689bd8beaa0cf93c2eef7a2a25723b46119d342b6158287cf9a748bd06c24d59e24156e2fc5405d2c7dcea0dfbaf1d6ba90e7c3cf1e60e9a2f8ea01c2c4d19193a025f2d51c2b533a9423a3e7b7a047562a1cf944815811f200ab5bc4c19cabb52e34a94e09459e591f27dec7ed1885ecf626d0db22a2717279cc7a6fd87e0cbc72134aa07750fc5c884952327dc1d6b9067a119d037693fbd0fa31013b38755d87ed711af9b3da5a246fe5873a41bb6dfab309c5938905b2d13bd299da2474ccaddb310b490970bbab447623e1bb5784940f29b1d3bf489507257e2e778995c27b998010d24735a537e8f0ac68a9f67cd1a017952c97f2de79a594cd6690257bea84989913ca83d487585335d9e00773753d7bd5573b92857d9cf96a4900b741d1700f475e9ffe236087653243c74a4dddd3490305838c1a85aea2cf32e39acb2441f248c6519c668798e5dba0686ec366801fe3c7dddb5729e021b34e388c1c0e4eace2dd2d77c33e71d1771f5408c319d370aa1aaaa515de479b138f5f6df6c33e22c376c7d277caab46b921e0faa7b642f20c5b1b24018b759f1f123b8753b7f57fda014ce0cd67d6cb7b419e8656e581808e02ea6511e8cb52e72810d106f21ef133fafcf193357a90be44482acb407147b97c568b43c8a4cd5ce22b0b2bc56ee740c08bdfca6edd947e9632859249ad4522a63e31961d81255bf80ad27a197ddbaed048500e34808abdc6d856a6ece7524df94a8493826acd0c88ab53d89a4e98709775112190f84f8de86eaa9a6643efbe271b2fde4a9fd3a15fe049dbc8b0d899f407a5188c8d66744490505c376c00018020acd6f03a53b160094deb984abbd9b2c7d7d65d5885417b942749fe3d03f5196326f664bdfc3ebeb51f4f6b53157af79b0ecf1ba67e04b6a41a0ca63f453e670bba4b00eb5ffb5e34e58edc45361410ca5a030fadbc339efb47c58b880c026f8d86bd15f745f1ab0d4a173a2f3a9c9d9213d3365640844dd3859da96cdf1dc120add4a6bacc4c9a637fd9370ab8004d79554920255008b263aa6b757812cf2367a6ad57eb69ba7b88c21a29697aabe184cde6ab8581ad0df7424b062ebefa9d9eeb9e543273e96a89747edc384f15fa9e349634c93e9ee5b75dbebfabd83504d95807f7c86bf1e89f1d312493a88a1188c01ef248eadb4744f9a5feab750f1878c461f6e94960b073f03c6bcbaf41ab2bac8e6385cbc54095cd5ac7b17a8b11d515614d28e25ee49ca97ffe40900650eb4a8ec2818154286f0ea9dda54f232e8e5aceec0d63c26663c7df892c3151860ff6c531a4c21f0e0e13349fe7641a59fc96ef62d9699972dcea298873f2f99b4f7ff00b69aa19717d378d6354c33911ae0fb42cc0127cae7fd2346ee6068b6c27e047aca46436e976456c14734490d0b04b1de5697fe6bf115c4c020fc939cb054d1b5c8cccdbea3dfba3e69a141656a98e8a3669ee18a4f889e66d84fbd2c45d859ad6088b7286cd8d815c3307ea1e19a8d47da200dded31f4e41af57f2a174605cb9f9379823105c494823a5a6e5e53edd5ab602f05fdf403dd26325a6acdea223b263e965640fed07fb62f8bda482c7d14797cfabd0c006d0566e10b899f08226e4e2bd1a28622af4f552503f41bc7ddadb3973ddc00969517ffca18d837ae830a3fbbd93a07904be5904db24ccb839bf9b70e629b35c676f6f9108f4d4749344e7ddf85262719caf7381f8069e3bf5af3acb0424323a6cf85c6a9d1b18a313963e29b32d308034507c5eac0ed600f12f74a9c7bfff3de9d547fd396914e0b3e56d0"
    shifts_hex = "1b7011ba4c40233fd54815751e3e0c81"

ciphertext = bytes.fromhex(ct_hex)
shifts_int = int(shifts_hex, 16)

# The 'shifts' string records the MSB (bit 127) of the nonce at every step.
# The 'shifts_hex' provided is the FINAL state of that string.
# Since the ciphertext is 2048 bytes (128 blocks), the loop ran 128 times.
# We extract the bits in chronological order.
shifts_bits = [(shifts_int >> (127 - i)) & 1 for i in range(128)]

# === 2. Recover the Initial KEY using Z3 ===
print("[*] Solver started, solving for KEY using Z3...")

# We are looking for the initial 128-bit KEY.
key_bv = BitVec('key', 128)

# The nonce starts as the KEY.
nonce = key_bv

# This tracks the 'shifts' variable in chal.py (numerical value).
accumulated_shifts = BitVecVal(0, 128)

solver = Solver()

# Simulate the loop in chal.py for 128 iterations
for i in range(128):
    known_bit = shifts_bits[i]
    
    # CONSTRAINT: The MSB of the current nonce MUST match the bit recorded in 'shifts'.
    # Extract(high_bit, low_bit, value)
    solver.add(Extract(127, 127, nonce) == known_bit)
    
    # Update 'shifts' numerical value: shifts = (shifts << 1) | new_bit
    accumulated_shifts = (accumulated_shifts << 1) | known_bit
    
    # Update nonce (chal.py logic): nonce = (nonce + int(shifts, 2)) & (MOD-1)
    nonce = nonce + accumulated_shifts
    
    # Update nonce (Rotate Left by 3)
    nonce = RotateLeft(nonce, 3)

# Check if a solution exists
if solver.check() == sat:
    model = solver.model()
    recovered_key_int = model[key_bv].as_long()
    KEY = long_to_bytes(recovered_key_int).rjust(16, b'\0')
    print(f"[+] Found Key: {KEY.hex()}")
else:
    print("[-] Unsatisfiable! The constraints are contradictory.")
    sys.exit(1)

# === 3. Decrypt the Ciphertext ===
# Now that we have the KEY, we reproduce the exact logic from chal.py to generate the keystream.

MOD = 1 << 0x80
N = 3

def rol(x, n): 
    return ((x << n) | (x >> (0x80 - n))) & (MOD-1)

def decrypt(ciphertext, key):
    nonce = bytes_to_long(key)
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    
    keystream_blocks = []
    current_shifts_str = ""
    
    # Calculate number of blocks (2048 / 16 = 128)
    num_blocks = len(ciphertext) // 16
    
    for _ in range(num_blocks):
        # 1. chal.py: shifts += f"{nonce >> 127:b}"
        current_shifts_str += f"{nonce >> 127:b}"
        
        # 2. chal.py: nonce = (nonce + int(shifts, 2)) & (MOD-1)
        shift_val = int(current_shifts_str, 2)
        nonce = (nonce + shift_val) & (MOD-1)
        
        # 3. chal.py: yield CIPHER.encrypt(nonce.to_bytes(16))
        ks_block = cipher.encrypt(nonce.to_bytes(16, 'big'))
        keystream_blocks.append(ks_block)
        
        # 4. chal.py: nonce = rol(nonce, N)
        nonce = rol(nonce, N)
        
    full_keystream = b"".join(keystream_blocks)
    
    # XOR decryption
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, full_keystream))
    return plaintext

print("[*] Decrypting...")
pt = decrypt(ciphertext, KEY)

# === 4. Extract Flag ===
try:
    # Look for the flag pattern
    match = re.search(b'nite\{.*?\}', pt)
    if match:
        print(f"\n[SUCCESS] Flag: {match.group(0).decode()}")
    else:
        print("\n[?] Flag pattern 'nite{...}' not found. Dumping plaintext:")
        print(pt)
except Exception as e:
    print(f"[-] Error parsing flag: {e}")

# nite{wh00ps_l34k3d_2_mUch}