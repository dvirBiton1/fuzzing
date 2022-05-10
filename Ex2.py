from scapy.all import *


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
