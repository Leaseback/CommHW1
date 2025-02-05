from scapy.all import rdpcap


def display_ethernet_header(packet):
    print("\nEthernet Header:")
    print(f"  Packet size: {len(packet)} bytes")
    print(f"  Destination MAC Address: {packet.dst}")
    print(f"  Source MAC Address: {packet.src}")
    print(f"  Ethertype: {hex(packet.type)}")


def display_ip_header(packet):
    if packet.haslayer("IP"):
        ip_packet = packet["IP"]
        print("\nIP Header:")
        print(f"  Version: {ip_packet.version}")
        print(f"  Header length: {ip_packet.ihl * 4} bytes")
        print(f"  Type of service: {ip_packet.tos}")
        print(f"  Total length: {ip_packet.len} bytes")
        print(f"  Identification: {ip_packet.id}")

        # Extract flags using bitwise operations
        flags = ip_packet.flags
        df_flag = bool(flags & 0x2)  # 0x2 corresponds to the DF (Don't Fragment) flag
        mf_flag = bool(flags & 0x1)  # 0x1 corresponds to the MF (More Fragments) flag

        print(f"  Flags: ")
        print(f"    Don't Fragment (DF): {df_flag}")
        print(f"    More Fragments (MF): {mf_flag}")

        print(f"  Fragment offset: {ip_packet.frag}")
        print(f"  Time to live: {ip_packet.ttl}")
        print(f"  Protocol: {ip_packet.proto}")
        print(f"  Header checksum: {hex(ip_packet.chksum)}")
        print(f"  Source IP: {ip_packet.src}")
        print(f"  Destination IP: {ip_packet.dst}")
    else:
        print("\nNo IP layer found in this packet.")


def display_tcp_header(packet):
    if packet.haslayer("TCP"):
        tcp_packet = packet["TCP"]
        print("\nTCP Header:")
        print(f"  Source port: {tcp_packet.sport}")
        print(f"  Destination port: {tcp_packet.dport}")
        print(f"  Sequence number: {tcp_packet.seq}")
        print(f"  Acknowledgment number: {tcp_packet.ack}")
        print(f"  Data offset: {tcp_packet.dataofs * 4} bytes")
        print(f"  Flags: {bin(tcp_packet.flags)}")
        print(f"  Window size: {tcp_packet.window}")
        print(f"  Checksum: {hex(tcp_packet.chksum)}")
        print(f"  Urgent pointer: {tcp_packet.urgptr}")
    else:
        print("\nNo TCP layer found in this packet.")

def display_udp_header(packet):
    if packet.haslayer("UDP"):
        udp_packet = packet["UDP"]
        print("\nUDP Header:")
        print(f"  Source port: {udp_packet.sport}")
        print(f"  Destination port: {udp_packet.dport}")
        print(f"  Length: {udp_packet.len}")
        print(f"  Checksum: {hex(udp_packet.chksum)}")
    else:
        print("\nNo UDP layer found in this packet.")

def display_icmp_header(packet):
    if packet.haslayer("ICMP"):
        icmp_packet = packet["ICMP"]
        print("\nICMP Header:")
        print(f"  Type: {icmp_packet.type}")
        print(f"  Code: {icmp_packet.code}")
        print(f"  Checksum: {hex(icmp_packet.chksum)}")
        print(f"  ID: {icmp_packet.id}")
        print(f"  Sequence: {icmp_packet.seq}")
    else:
        print("\nNo ICMP layer found in this packet.")

def pktsniffer(pcap_file):
    packets = rdpcap(pcap_file)

    for packet in packets:
        display_ethernet_header(packet)
        display_ip_header(packet)

        # Check for encapsulated protocols and display respective headers
        if packet.haslayer("TCP"):
            display_tcp_header(packet)
        elif packet.haslayer("UDP"):
            display_udp_header(packet)
        elif packet.haslayer("ICMP"):
            display_icmp_header(packet)

if __name__ == "__main__":
    # Specify the path to your .pcap file
    pcap_file = "C:\\Users\\Kyle\\Downloads\\test.pcap"
    pktsniffer(pcap_file)
