# FILE: core/sniffer.py
# PURPOSE: Handles all packet sniffing logic using Scapy.
# ==============================================================================
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet, queue, local_ip):
    """Places relevant packet info into a queue for processing."""
    try:
        if IP not in packet or not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return

        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if src_ip != local_ip and dst_ip != local_ip:
            return

        proto = packet.getlayer(TCP) or packet.getlayer(UDP)
        conn_tuple = (src_ip, proto.sport, dst_ip, proto.dport)
        direction = "out" if src_ip == local_ip else "in"
        remote_ip = dst_ip if direction == "out" else src_ip
        queue.put((conn_tuple, direction, remote_ip))
    except Exception:
        pass

def start_monitoring(interface, queue, local_ip):
    """Target function for the sniffing process."""
    print(f"\n[Sniffer] Starting monitoring on interface: {interface} ({local_ip})")
    try:
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, queue, local_ip), store=0)
    except Exception as e:
        print(f"\n[Sniffer] An error occurred: {e}")