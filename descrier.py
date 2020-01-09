import sys
if sys.version_info[0] != 3:
    exit("Must be run with python3")
from scapy.all import *
from netaddr import IPNetwork #pip3 install netaddr
hosts = {}

class flags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


#DEBUG = True
DEBUG = False
def debug(string,verbose=True):
    if DEBUG:
        if verbose:
            print("[DEBUG] {}".format(string))
        else:
            return "[DEBUG] {}".format(string)

def process(packet):
    if packet.haslayer(TCP) and (packet[TCP].flags & flags.SYN) and (packet[TCP].flags & flags.ACK):
        basic = str(packet.summary())
        debug(basic)
        #Ether / IP / TCP 192.168.0.15:5357 > 192.168.0.44:46632 SA
        src = basic.split(" > ")[0]
        src = src.split("TCP ")[1]
        
        if src.count(":") == 1:
            host,summary = src.split(":",1)
            port = packet[TCP].sport
        else:
            #Discovered open port 443 on host 2607 (f**0:4**4:8*7::2**2:https)
            host = src.rsplit(":",1)[0]
            summary = src.split(":")[-1]
            port = packet[TCP].sport
        if scope and str(host) not in scope:
            #print("Host not in scope {}".format(host))
            return

        if host in hosts:
            knownports = hosts[host]
            known = False
            for testport in knownports.split(","):
                if str(port) == str(testport).replace(",","").replace(" ",""):
                    known = True
            if not known:
                hosts[host] += ",{}".format(str(port))
        
        elif host not in hosts:
            hosts[host] = str(port)
            known = False 
        
        if not known:
            print("Discovered open port {} on host {} ({})".format(port,host,summary))
    
    #else:
    #    debug(packet.summary())

def sniff_packet(iface):
    try:
        sniff(iface=iface,store=False,prn=process)
    except Exception as e:
        print(e)
        return "Terminated"
    #for packet in packets:
    #    print(process(packet))

try:
    iface = sys.argv[1]
except:
    exit("Usage: python3 descrier.py <interface> (scope) (outfile)")
try:
    allowed = sys.argv[2]
    scope = []
    for ip in IPNetwork(allowed):
        scope.append(str(ip))
except:
    scope = None
try:
    outfile = sys.argv[3]
except:
    outfile = None

print("Initializing sniff")
#while True:
sniff_packet(iface)
print("\nResults:")
if outfile:
    f = open(outfile,"w")
for host in hosts:
    string = str("{} | {} ({} port(s) open)".format(host,hosts[host],len(hosts[host].split(","))))
    print(string)
    if outfile:
        f.write(string)
        f.write("\n")
if outfile:
    f.close()
