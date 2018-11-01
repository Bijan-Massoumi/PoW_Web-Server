
import random
import string


f = open("input.txt","w")
for i in range(100):
    user_len = random.randint(1,20)
    pass_len = random.randint(0,20)
    userName = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-" + "_" + ".", k=user_len))
    password = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=pass_len))
    f.write(userName + " " + password + "\n")

f.close()
