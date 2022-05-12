import time
from datetime import datetime

def log_scanner():
    fuzz1 = 0
    flag = 0
    fuzzAttck = 1
    filesize = 0
    while fuzzAttck:
        with open("/var/log/auth.log","r") as f:
            lines = f.readlines()
            if len(lines) != filesize:
                for l in range(filesize, len(lines)):
                    # print(l)
                    # print(lines[l])
                    p =lines[l].split()
                    if ("error:" in p or ("Connection" in p and "closed" in p) or ("banner" in p and "exchange" in p) )and flag:
                        fuzz1 += 1
        if fuzz1 >= 5 and flag:
            print(fuzz1)
            print("fuzzing attack")
            exit(0)
        else:
            flag = 1
        time.sleep(5)
        print(f"fuzz1 = {fuzz1}")
        filesize = len(lines)

if __name__ == '__main__':
    log_scanner()
