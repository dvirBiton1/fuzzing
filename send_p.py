
import socket
from scapy.all import *
from scapy.layers.inet import *

send(IP(dst="127.0.0.1")/TCP(dport=22)/"hello name cd aaa") #you can change the input
