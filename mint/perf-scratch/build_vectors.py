#!/usr/bin/env python3
"""Build raw L2 frames (.bin) for each perf vector, as XDP PROG_TEST_RUN data_in."""
import socket, struct, sys, os

OUT = os.path.dirname(os.path.abspath(__file__))

def mac(s): return bytes(int(b,16) for b in s.split(":"))

def ipcsum(h):
    if len(h)%2: h+=b"\x00"
    s=0
    for i in range(0,len(h),2):
        s+=(h[i]<<8)|h[i+1]; s=(s&0xffff)+(s>>16)
    return (~s)&0xffff

def eth(dst,src,ethertype,payload=b""):
    f = mac(dst)+mac(src)+struct.pack("!H",ethertype)+payload
    if len(f) < 60: f += b"\x00"*(60-len(f))
    return f

def ipv4(src_ip,dst_ip,proto=17,sport=0,dport=0,vlan=None):
    # 20B IPv4 + 8B UDP/TCP-ish L4 header so dst_port axis is readable
    if proto==17:  # UDP
        l4 = struct.pack("!HHHH",sport,dport,8,0)
    elif proto==6: # TCP minimal 20B
        l4 = struct.pack("!HHIIBBHHH",sport,dport,0,0,(5<<4),0,0,0,0)
    else:
        l4 = b""
    total = 20+len(l4)
    iph = struct.pack("!BBHHHBBH4s4s",(4<<4)|5,0,total,0,0x4000,64,proto,0,
                      socket.inet_aton(src_ip),socket.inet_aton(dst_ip))
    iph = struct.pack("!BBHHHBBH4s4s",(4<<4)|5,0,total,0,0x4000,64,proto,
                      ipcsum(iph),socket.inet_aton(src_ip),socket.inet_aton(dst_ip))
    body = iph+l4
    if vlan is None:
        return eth("ff:ff:ff:ff:ff:ff","02:00:00:00:00:01",0x0800,body)
    tag = struct.pack("!HH",0x8100,vlan)+struct.pack("!H",0x0800)
    f = mac("ff:ff:ff:ff:ff:ff")+mac("02:00:00:00:00:01")+tag+body
    if len(f)<60: f+=b"\x00"*(60-len(f))
    return f

def arp_frame():
    # bare ARP ethertype 0x0806, minimal arp body
    body = struct.pack("!HHBBH6s4s6s4s",1,0x0800,6,4,1,
                       mac("02:00:00:00:00:01"),socket.inet_aton("10.0.0.1"),
                       mac("00:00:00:00:00:00"),socket.inet_aton("10.0.0.2"))
    return eth("ff:ff:ff:ff:ff:ff","02:00:00:00:00:01",0x0806,body)

def write(name,data):
    p=os.path.join(OUT,name)
    with open(p,"wb") as f: f.write(data)
    print(f"{name:28s} {len(data):4d}B")

if __name__=="__main__":
    # non-IP early exit: ARP
    write("v_nonip.bin", arp_frame())
    # v4 single-rule cidr: config_valid_cidr passes src 10.0.0.0/8 -> use src 10.5.6.7
    write("v_v4_1rule.bin", ipv4("10.5.6.7","192.0.2.1",proto=17,dport=1234))
    # v4 matched 64-rule: dst 10.0.63.5 hits the highest-id rule (10.0.63.0/24).
    write("v_v4_64rule.bin", ipv4("203.0.113.1","10.0.63.5",proto=17,dport=80))
    # v4 NOMATCH: src/dst outside every axis
    write("v_v4_nomatch.bin", ipv4("203.0.113.9","198.51.100.9",proto=17,dport=9999))
    print("v6+ext built separately via scapy (build_v6.py)")
