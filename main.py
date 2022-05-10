from itertools import count

import enchant
# from enchant.checker import SpellChecker
from scapy.all import *
# from enchant import *
from enchant.checker.CmdLineChecker import CmdLineChecker
from enchant.checker import SpellChecker

d2 = enchant.DictWithPWL("en_US","list_commands.txt")
chkr = SpellChecker("en_US")


def filter_packet(p):
    p.show()
    data = p[Raw].load
    s = p[IP].src
    print(s)
    # print(data.decode())
    decode_data = data.decode()
    chkr.set_text(decode_data)
    txt = decode_data.split(" ")
    for err in txt:
        if d2.check(err) == False:
            print("fuzzing detected:", err)

    # for err in chkr:
    #


if __name__ == '__main__':
    sniff(iface="lo", filter="tcp port 22", prn=filter_packet)
# enp0s3
# ask daniel about buffer overflow