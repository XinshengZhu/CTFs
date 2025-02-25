import random
import struct
import hashlib

# ran time.time() right when I accessed the server
estimated_time = 1737867677.0612311

0.000001

def generate_session_token(username, password, seed_time, offset):
    """
    Generates a session token using the same method as the server file provided.
    """
    random.seed(int.from_bytes(struct.pack('<d', seed_time), byteorder='little'))

    # get to the right offset of rand() by calling it by num of offset times
    for i in range(offset):
        junk = random.randbytes(5)

    random_bytes = random.randbytes(5)
    session_token = hashlib.md5(
        username.encode('utf-8') + b":" + password.encode('utf-8') + b":" + random_bytes
    ).hexdigest()
    return session_token


the_edit_time = estimated_time-2
the_end_time = estimated_time+2

test_key = "1841052546cdb0b5e031fdad79e02be7"
while the_edit_time<the_end_time:
    print(the_edit_time)
    if generate_session_token("test", "test", the_edit_time, 3)==test_key:
        print("FOUND TIME FOR SEED.", the_edit_time)
        break
    the_edit_time+=0.000001


# for the fake user, we have the password, username and just need the exact time used for seed...
"""
USERNAME        SESSION TOKEN
davy-jones      41dc6d1042f74adaa2202499e5a39ec5 (offset 0)
bob             50cc954a1551a86c461015b3a5f24741 (offset 1)
blackbeard      aaa86f4a5a0a6801f3cb8cf07acb85f1 (offset 2)
test            1841052546cdb0b5e031fdad79e02be7 (offset 3)
"""
users = [
    {
        "username": "davy-jones",
        "hash": "41dc6d1042f74adaa2202499e5a39ec5",
        "offset": 0
    },
    {
        "username": "bob",
        "hash": "50cc954a1551a86c461015b3a5f24741",
        "offset": 1
    },
    {
        "username": "blackbeard",
        "hash": "aaa86f4a5a0a6801f3cb8cf07acb85f1",
        "offset": 2
    }
]

# discovered time for seed...
final_time = the_edit_time

# used rockyou password dictionary
password_file = "passwords.txt"
with open(password_file, 'r') as file:
    passwords = [line.strip() for line in file]

for user in users:
    for password in passwords:
        if generate_session_token(user['username'], password, final_time, user['offset'])==user['hash']:
            print(f"FOUND PASSWORD FOR USER {user['username']}")
            print(password)
            break


# davy jones pass: kingof7seas
# bob pass: password123
# blackbear pass: lochnessmonster

# FLAG: TUCTF{k4p714n_KR4K3N_Kn33lS_83f0r3_y0U_329481!}