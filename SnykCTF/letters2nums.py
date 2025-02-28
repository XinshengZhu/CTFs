encflag = open('encflag.txt', 'r').read().strip().split('\n')
decflag = ''
for i in range(len(encflag)):
    arg2 = int(encflag[i])&0xFF
    arg1 = (int(encflag[i])>>8)&0xFF
    decflag += chr(arg1)+chr(arg2)
print(decflag)

# flag{3b050f5a716e51c89e9323baf3a7b73b}