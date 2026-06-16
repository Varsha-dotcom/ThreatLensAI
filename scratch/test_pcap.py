import os
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

def create_dummy_pcap(filename):
    print("Generating mock packets using Scapy...")
    packets = []
    
    t = 1600000000.0
    
    # 1. Normal HTTP connection flow (TCP)
    # SYN, SYN-ACK, ACK, Data, FIN
    p1 = IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="S")
    p1.time = t
    p2 = IP(src="8.8.8.8", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="SA")
    p2.time = t + 0.05
    p3 = IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="A")
    p3.time = t + 0.1
    p4 = IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="PA")/Raw(load="GET /index.html HTTP/1.1\r\n\r\n")
    p4.time = t + 0.15
    p5 = IP(src="8.8.8.8", dst="192.168.1.10")/TCP(sport=80, dport=12345, flags="PA")/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789")
    p5.time = t + 0.2
    
    packets.extend([p1, p2, p3, p4, p5])
    
    # 2. DoS attack flow (SYN flood)
    t_dos = t + 5.0
    for i in range(40):
        p_syn = IP(src="10.0.0.5", dst="192.168.1.50")/TCP(sport=20000+i, dport=135, flags="S")
        p_syn.time = t_dos + i*0.01
        packets.append(p_syn)
        
    # 3. Probe flow (Satan scanner)
    t_probe = t + 10.0
    ports = [21, 22, 23, 25, 53, 80, 110, 443, 8080, 3389]
    for idx, p in enumerate(ports):
        p_scan = IP(src="192.168.1.99", dst="192.168.1.50")/TCP(sport=54321, dport=p, flags="S")
        p_scan.time = t_probe + idx*0.1
        packets.append(p_scan)
        
    # 4. Normal DNS connection (UDP)
    t_udp = t + 15.0
    p_udp1 = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=32110, dport=53)/Raw(load="DNS query")
    p_udp1.time = t_udp
    p_udp2 = IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=32110)/Raw(load="DNS response")
    p_udp2.time = t_udp+0.05
    packets.extend([p_udp1, p_udp2])
    
    # 5. ICMP Ping request/reply
    t_icmp = t + 20.0
    p_icmp1 = IP(src="192.168.1.10", dst="8.8.8.8")/ICMP(type=8, code=0)
    p_icmp1.time = t_icmp
    p_icmp2 = IP(src="8.8.8.8", dst="192.168.1.10")/ICMP(type=0, code=0)
    p_icmp2.time = t_icmp+0.05
    packets.extend([p_icmp1, p_icmp2])
    
    print(f"Writing {len(packets)} packets to PCAP: {filename}")
    wrpcap(filename, packets)
    print("PCAP file generated successfully.")

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_pcap = os.path.join(base_dir, "scratch", "traffic_test.pcap")
    os.makedirs(os.path.dirname(target_pcap), exist_ok=True)
    create_dummy_pcap(target_pcap)
