import random
from random import randint

# Recreate the same grid used for encryption
def create_grid():
    random.seed(3211210)
    arr = ['j', 'b', 'c', 'd', '2', 'f', 'g', 'h', '1', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'y',
           'v', '3', '}', '{', '_']
    t = []
    for i in range(len(arr), 0, -1):
        l = randint(0, i-1)
        t.append(arr[l])
        arr.remove(arr[l])
        arr.reverse()
    return t

# Print the grid for visualization
def print_grid(grid):
    for i in range(5):
        row = grid[i*5:(i+1)*5]
        print(' '.join(row))

# Decrypt function that reverses the encryption process
def decrypt(ciphertext, grid):
    plaintext = ''
    for k in range(0, len(ciphertext)-1, 2):
        c1, c2 = ciphertext[k], ciphertext[k+1]
        q1, q2 = grid.index(c1), grid.index(c2)
        
        row1, col1 = q1 // 5, q1 % 5
        row2, col2 = q2 // 5, q2 % 5
        
        # Same row
        if row1 == row2:
            plaintext += grid[row1*5 + (col1-1)%5]
            plaintext += grid[row2*5 + (col2-1)%5]
        # Same column
        elif col1 == col2:
            plaintext += grid[((row1-1)%5)*5 + col1]
            plaintext += grid[((row2-1)%5)*5 + col2]
        # Rectangle rule (same in both directions)
        else:
            plaintext += grid[row1*5 + col2]
            plaintext += grid[row2*5 + col1]
    
    return plaintext

# Main execution
grid = create_grid()
encrypted = "yjp}b{k{_vog1pnb2j31dhs1bsptln"

print("5x5 Grid:")
print_grid(grid)
print("\nEncrypted text:", encrypted)
decrypted = decrypt(encrypted, grid)
print("Decrypted result:", decrypted)

# Let's also try to encrypt our decrypted result to verify it matches the original ciphertext
def encrypt(plaintext, grid):
    ciphertext = ''
    for k in range(0, len(plaintext)-1, 2):
        p1, p2 = plaintext[k], plaintext[k+1]
        q1, q2 = grid.index(p1), grid.index(p2)
        
        row1, col1 = q1 // 5, q1 % 5
        row2, col2 = q2 // 5, q2 % 5
        
        # Same row
        if row1 == row2:
            ciphertext += grid[row1*5 + (col1+1)%5]
            ciphertext += grid[row2*5 + (col2+1)%5]
        # Same column
        elif col1 == col2:
            ciphertext += grid[((row1+1)%5)*5 + col1]
            ciphertext += grid[((row2+1)%5)*5 + col2]
        # Rectangle rule
        else:
            ciphertext += grid[row1*5 + col2]
            ciphertext += grid[row2*5 + col1]
    
    return ciphertext

# Verify our solution
re_encrypted = encrypt(decrypted, grid)
print("\nRe-encrypted result:", re_encrypted)
print("Original ciphertext:", encrypted)
print("Verification:", "MATCH" if re_encrypted == encrypted else "MISMATCH")

# jctf{python_r3v3rs1ng_c22b3b1}