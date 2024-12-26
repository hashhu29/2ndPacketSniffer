from scapy.all import sniff, IP, TCP
def packets(packet):
    if IP in packets:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print('source IP: {src_ip} destination IP: {dst_ip}')

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print('source port: {src_port} destination port{dst_port}')

sniff(prn=packets, count=10)

