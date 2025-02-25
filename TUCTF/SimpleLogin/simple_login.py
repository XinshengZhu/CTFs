username = "TheSuperSecureAdminWhoseSecretWillNeverBeGotten"
password = "ruint"
flag = ""

part1 = [84, 85, 67, 84, 70]
flag += "".join([chr(i) for i in part1])

flag += "{"

part2 = "Z]AWB@WA"
password += "".join([chr(ord(i) ^ 0x32) for i in part2])

part3 = [26, 26, 29, 11, 25, 28, 2, 44]
flag += "".join([chr(ord(i) ^ 0x32 ^ part3[part2.index(i)]) for i in part2])

part4 = "reingvbaonetr"

password += "".join([chr(ord(i) - 97 + 84) for i in part4])

part5 = "guebhtu_gur_fhoebhgvarf!!}"

for i in range(len(part5)):
    num = ord(part5[i])
    if num > 122 or num < 97:
        flag += chr(num)
    else:
        flag += chr((ord(part5[i]) - 84) % 26 + 97)

print("Password: " + password)
print("Flag: " + flag)

# Password: ruinthosepreseX\aZiUTbaXge
# Flag: TUCTF{running_through_the_subroutines!!}
