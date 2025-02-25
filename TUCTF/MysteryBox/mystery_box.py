encrypted = b"\x0e\x0f\x19\x0e\x1c!\x18;4;4;\x05\t591)\'".decode("utf-8")
decrypted = ""

for i in range(len(encrypted)):
    decrypted += chr(ord(encrypted[i]) ^ 0x5a)

print(decrypted)

# TUCTF{Banana_Socks}
