from cryptography.fernet import Fernet

key = b"UIYfpIrqvzvTedjR1qFm66K1MYYlwNgUQlgpZPfLs3k="
cipher = Fernet(key)

ciphertext = b"gAAAAABnSr5MS-gH-RLqtV1ltw_hBuwujvt6S-Ku3pOdgSpAiby55EGOI3JMpv3JX6ptlhnC8cT4UdfqiIck6RDgobhASUKPJlZMkV0Js82Xx-kIHKywirHeGBqKQimJ672sPnbeWL1e"

plaintext = cipher.decrypt(ciphertext)
print(plaintext)

# TUCTF{1T$__t0rn@d0$zn__nz$0d@nr0t__$T1}
