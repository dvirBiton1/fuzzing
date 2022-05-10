from scapy.all import *
from scapy.layers.inet import TCP

ftpconns = {}
faildftp = {}

def ftpAnalysis(p):
    p.show()
    vals = p[Raw].load.strip().split()
    src = p[IP].src
    dst = p[IP].dst
    port = p[TCP].sport
    if vals[0] == b"USER":
        key = "%s ->%s " % (src,dst)
        if not key in ftpconns:
            ftpconns[key] = {}
        ftpconns[key][port]= [vals[1].decode("utf-8"),"login"]
    elif vals[0] == b"PASS":
        key = "%s ->%s " % (src, dst)
        if key in ftpconns:
            if port in ftpconns[key]:
                ftpconns[key][port] = "pass"
            else:
                print(f"anomalous ftp pass {vals[1]} {key}:{port}")
    elif vals[0] == b"530":
        key = "%s ->%s " % (dst,src)
        port =p[TCP].dport
        if key in ftpconns:
            if port in ftpconns[key]:
                v = ftpconns[key].pop(port)
                if v[0] in faildftp:
                    faildftp[v[0]] += 1
                else:
                    faildftp[v[0]] = 1
sshconns = {}
faildssh= {}
threshold = 5000
def sshAnalysis(p):
    sip = p[IP].src
    cip = p[IP].dst
    key = "%s->%s" % (cip, sip)
    port = p[TCP].dport
    l = p[IP].len +14
    if "F" in p[TCP].flags:
        b = sshconns[key].pop(port)
        b += 1
        if b < threshold:
            print("fuzzing!")
    #         if key in faildssh:
    #             faildssh[key] += 1
    #         else:
    #             faildssh[key] += 1
    # else:
    #     if not key in sshconns:
    #         sshconns[key] = {}
    #     if port in sshconns[key]:
    #         sshconns[key][port] += 1
    #     else:
    #         if "S" in p[TCP].flags:
    #             sshconns[key][port] = 1
def analyzePacket(p):
    if p.haslayer(TCP):
        if (p[TCP].sport == 21 or p[TCP].dport == 21) and p.haslayer(Raw):
            ftpAnalysis(p)
        elif (p[TCP].sport == 22):
            sshAnalysis(p)
def printResults(openConns, failed, protocol):
    print(f"open {protocol} connections:")
    for conn in openConns:
        c = openConns[conn]
        if len(c) > 0:
            print(conn)
            for p in c:
                print(f"\t port: {(p,c[p])} user:")
    print(f"faild {protocol} logins:")
    for f in failed:
        print(f"\t {(f, failed[f])}")

if __name__ == '__main__':
    sniff(offline="ssh.pcapng", prn=analyzePacket)
    # sniff(iface="enp0s3", filter="port 22", prn=analyzePacket)
    # printResults(sshconns,faildssh, "SSH")