from scapy.all import *
from scapy.layers.inet import TCP
sum = []
faildssh = {}
threshold = 5000
b = 0

def sshAnalysis(p):
    global b
    sip = p[IP].src
    cip = p[IP].dst
    key = "%s->%s" % (cip, sip)
    port = p[TCP].dport
    l = p[IP].len + 14
    if "F" in p[TCP].flags:
        for s in sum:
            b += s
        if b < threshold:
            faildssh[key] = port
            print("fuzzing!")
            # exit(0)
        else:
            print("good connection")
    else:
        sum.append(l)


def analyzePacket(p):
    if p.haslayer(TCP):
        if (p[TCP].sport == 22):
            sshAnalysis(p)


def printResults(failed, protocol):
    print(f"{protocol} faild connections:")
    for f in failed:
        print(f"\t {(f, failed[f])}")


if __name__ == '__main__':
    sniff(offline="ssh.pcapng",prn=analyzePacket)
    # sniff(iface="enp0s3", filter="port 22", prn=analyzePacket)
    printResults(faildssh, "SSH")
