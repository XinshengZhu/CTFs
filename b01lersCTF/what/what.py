from typing import List

def simulate_chunk(ch: int, ops: str, idx: int) -> tuple[int, int]:
    """
    Simulates operations on a character based on the WHAT algorithm.
    
    Args:
        ch: The ASCII value of the character being processed
        ops: String of operations to perform (W, H, A)
        idx: Current index in the WHAT array
        
    Returns:
        Tuple of (resulting value, new index)
    """
    what = [ord(c) for c in "WHAT"]  # Convert "WHAT" to ASCII values
    acc = ch  # Initialize accumulator with the character value
    
    # Process each operation
    for op in ops:
        if op == 'W':
            acc ^= what[idx]  # XOR operation
        elif op == 'H':
            acc += what[idx]  # Addition operation
        elif op == 'A':
            acc *= what[idx]  # Multiplication operation
        
        acc &= 0xFFFFFFFFFFFFFFFF  # Limit to 64 bits
        idx = (idx + 1) % 4  # Cycle through the WHAT array
        
    return acc, idx

def decode_sequence(program: str, solution: List[int]) -> str:
    """
    Decodes a sequence of operations to recover the original text.
    
    Args:
        program: String containing operations and markers
        solution: List of target values to match
        
    Returns:
        Decoded string (the flag)
    """
    result = ""
    program_idx = 0
    what_idx = 0
    solution_idx = 0

    # Process the program string
    while program_idx < len(program):
        # When we encounter a '?', we need to find a character
        if program[program_idx] == '?':
            program_idx += 1
            operations = ""
            
            # Collect operations until we hit 'T'
            while program_idx < len(program) and program[program_idx] != 'T':
                operations += program[program_idx]
                program_idx += 1
            program_idx += 1  # Skip the 'T'

            # Get the target value we need to match
            target = solution[solution_idx]
            solution_idx += 1

            char_found = False
            matching_chars = []
            
            # Try all printable ASCII characters
            for char in range(0x20, 0x7f):  # 0x20 (space) to 0x7e (~)
                acc, idx = simulate_chunk(char, operations, what_idx)
                
                # If this character produces the target value
                if acc == target:
                    matching_chars.append(chr(char))
                    char_found = True
                    what_idx = idx  # Update the WHAT index for next chunk
            
            # Handle the results
            if char_found:
                if len(matching_chars) == 1:
                    result += matching_chars[0]
                else:
                    # If multiple matches, use the first but warn
                    result += matching_chars[0]
                    print(f"Multiple matches found for target {hex(target)}: {matching_chars}")
            else:
                # No match found
                result += '?'
                print(f"No match found for target {hex(target)} with operations {operations}")
        else:
            # Skip any character that's not a '?'
            program_idx += 1

    return result

# The encoded program string (sequence of operations)
program = "?WAWWHT?WAAWWAHHWAWAAAT?WAAHAAHHAAT?WHAAAHAHAWWHT?WHAAHHAHAWHT?WWHHWWHAAAHHWHT?WHHHHHHHAAT?WHHHHHHWWAHHT?WHAAAHAHAWHHHHHAAHT?WHHWHHAHHAAAHAAHHHT?WHHHAHWHHHAHHHAHAAT?WAAHHAHHHAHHWHHHHHT?WHHHHAHHAHAHWHHHHHT?WHHHHHHHWAHHAHHHHHT?WAWT?WHAAAAAAAWT?WHAAHAAAWAWWT?WAAAHAWAWHHT?WAAAHHHHAT?WAHHWHAHAHT?WAHHHHWWHWHAT?WAHWHHHWHHHT?WAHHAAAHHAAHHAHHT?WHHHAHWWHAHAHAWHHAAT?WAHWHHHWAAHHHWAHHHAWT?WAHHHHHAAHHHWHAHHT?WHHHHHAHHAHHHHHAT?WHHHHHHWWHAHWHHHAHHT?WHHHHHHWHHWHWHWHHHAHT?WAAWAAAAAT?WHAAAAAWWAT?WAWWHWWHAAAAT?WAAAAWWHHHWT?WHAHHAAHWT?WHWHWAHHAHT?WHAHHWWWHWHHT?WHHAHHHHAAAWHAAWAWT?WWAWHAHHHAHHAWHAAHT?WHHAHHHHWAAHAWHHAWT?WAHHAHWAHHWHHAHWHHT?WHAHHHHWHHAWHHHWAHT?WWHWAHHHHHHHAHHHHWT?WHHWWHHWHAHHHHHHHHT?WHWHHHHHAAHWAHHHHAAHAHWHAT?WAAAAAAT?WWAAWHAWAWAT?WAAAWAHWHT?WHAHWAHAWWT?WHHHHAAT?WWHAHHHHWWWT?WHHWAWAAAHAHAHHAT?WHAAHHAHAAHAHHT?WWAHHHHHAHHHAAAT?WAHAHHHWHHAHHHWWAT?WHHHHHAWHAHHHWAHT?WHHHHHAHAHHHHHT?WHHHWHHAHHHHHHHT?WHHAHHHWAHAHAWHHAHAAHHHWT?WHAHAHWHHWHAHAAHHHHWHWHAHT?WAAAWAAT?WAAAAHT!"

# Target values that our decoded characters should produce (array of solutions)
solution = [0x0000000000000f54, 0x00016f4a5e260570, 0x000009bd5485c77c, 0x000000523e921c64, 0x0000000131a573ad, 0x0000000008f0366a, 0x000000000031923c, 0x0000000000008045, 0x0007bdd4f2f841e4, 0x000095916508bfe9, 0x0000008be32212f8, 0x0000000096a96236, 0x0000000008f505cc, 0x00000000002ba72f, 0x0000000000000d79, 0x00067f100a7fe057, 0x0000165f086e2afb, 0x0000000e629b2305, 0x000000004759f2cc, 0x0000000001067699, 0x0000000000015e23, 0x0000000000000fed, 0x000a58a6ff5e80c3, 0x0000420719f56d10, 0x0000000de2c53af7, 0x00000000869bf143, 0x000000000da18d18, 0x00000000003b669b, 0x0000000000010197, 0x0002f5ff57445d00, 0x00002d028a7a55f4, 0x00000016d07ce160, 0x000000005dc6247d, 0x0000000002b0a9cd, 0x00000000001ee163, 0x000000000000442c, 0x0010deb1377a1730, 0x000015288f08a6d8, 0x000000769ffa893b, 0x0000000016c9a3fc, 0x00000000042356fe, 0x00000000001ca845, 0x000000000000ae04, 0x002acbc4c1348ca7, 0x0000156652f56900, 0x000000141a6b0269, 0x0000000085044ca1, 0x0000000004233d6b, 0x000000000027cf3c, 0x0000000000003279, 0x0011ab80fced20e4, 0x00001d631a31a393, 0x000000414d72a784, 0x000000005e787f58, 0x0000000013497804, 0x0000000000260b58, 0x0000000000009a54, 0x000a5d9dfc502eaa, 0x0000135ac1bc1242, 0x00000018d84f7478, 0x000000005394c6b7]

# Decode the flag
flag = decode_sequence(program, solution)
print("Flag:", flag)

# bctf{1m_p3rplexed_to_s4y_th3_v3ry_l34st_rzr664k1p5v2qe4qdkym}