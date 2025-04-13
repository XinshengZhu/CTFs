import base64
import re
import zlib

# Open and read the challenge file
with open('chal.txt', 'r') as file:
    content = file.read()

# Find all code objects with names consisting of 'a' and 'b' characters
ab_matches = re.findall(r'Disassembly of <code object ([ab]+) at', content)

# Dictionary to store the mapping between ab patterns and their corresponding underscore patterns
ab_underscore_dict = {}

# For each ab pattern, find the first underscore pattern associated with it
for ab_match in ab_matches:
    # Find the position of the code object in the content
    ab_match_pos = content.find(f"Disassembly of <code object {ab_match} at")
    # Search for the first underscore pattern after the code object
    first_underscore_match = re.search(r"'([_ ]+)'", content[ab_match_pos:])
    if first_underscore_match:
        # Store the mapping between ab pattern and underscore pattern
        ab_underscore_dict[ab_match] = first_underscore_match.group(1)

# Find the 'z' code object
z_match = re.findall(r'Disassembly of <code object ([z_]+) at', content)[0]
# Find the position of the z code object
z_match_pos = content.find(f"Disassembly of <code object {z_match} at")
# Find all ab patterns referenced in the z code object
ab_matches_in_z = re.findall(r"\(([ab]+) \+ NULL\)", content[z_match_pos:])
# Reverse the order of ab patterns (important for correct decoding)
ab_matches_in_z = ab_matches_in_z[::-1]

# Start building the encoded compressed flag with 'c' as the first character
encoded_compressed_flag= "c"

# For each ab pattern referenced in z, convert its underscore pattern to characters
for ab_match_in_z in ab_matches_in_z:
    # Convert underscore patterns to characters by calculating length - 27
    encoded_compressed_flag += ''.join(chr(len(c) - 27) for c in ab_underscore_dict[ab_match_in_z].split(' '))

# Decode the base85 encoded string to get the compressed flag
compressed_flag = base64.b85decode(encoded_compressed_flag)

# Decompress the flag using zlib
flag = zlib.decompress(compressed_flag)

# Print the decoded flag
print(f"Flag: {flag.decode()}")

# texsaw{python_4_will_never_exist_but_if_it_did_it_might_look_like_this_maybe_but_no_one_can_be_for_sure_did_yall_use_chatgpt_for_this?_let_me_know_if_so}