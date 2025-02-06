import argparse

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


def pktsniffer(pcap_file, host=None, port=None, ip=None, tcp=False, udp=False, icmp=False, net=None):
    packets = rdpcap(pcap_file)

    for packet in packets:

        # If host command is given, filter out all packets without matching src or dst ip
        if host:
            if packet.haslayer("IP"):
                ip_packet = packet["IP"]

                # If packet IP does not match host ip move onto next packet
                # Otherwise continue filtering based off of other filters
                if host != ip_packet.src and host != ip_packet.dst:
                    continue
            else:
                continue

        # If port command is given, filter out all packets without matching port
        if port:
            if packet.haslayer("TCP"):
                if port != packet["TCP"].sport and port != packet["TCP"].dport:
                    continue
            if packet.haslayer("UDP"):
                if port != packet["UDP"].sport and port != packet["UDP"].dport:
                    continue

        # if packet.haslayer("IP"):
        #     ip_packet = packet["IP"]
        #     if ip != ip_packet.src and ip != ip_packet.dst:
        #         continue

        # If it is a TCP packet and --udp flag is not on
        if packet.haslayer("TCP") and udp is False and icmp is False:
            display_ip_header(packet)
            display_tcp_header(packet)

        if packet.haslayer("UDP") and tcp is False and icmp is False:
            display_ip_header(packet)
            display_icmp_header(packet)

        if packet.haslayer("ICMP") and tcp is False and udp is False:
            display_ip_header(packet)
            display_udp_header(packet)

        elif icmp and packet.haslayer("ICMP"):
            display_ethernet_header(packet)
            display_ip_header(packet)
            display_icmp_header(packet)


def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Network Packet Analyzer (pktsniffer)")

    # Required argument for pcap file
    parser.add_argument("-r", "--pcap_file", type=str, help="Path to the .pcap file to analyze", required=True)

    # Optional arguments
    parser.add_argument("--host", nargs="?", type=str, help="Filter packets by host IP address")
    parser.add_argument("--port", nargs="?", type=int, help="Filter packets by port")
    parser.add_argument("--ip", nargs="?", type=str, help="Filter packets by source or destination IP")
    parser.add_argument("--tcp", action="store_true", help="Filter only TCP packets")
    parser.add_argument("--udp", action="store_true", help="Filter only UDP packets")
    parser.add_argument("--icmp", action="store_true", help="Filter only ICMP packets")
    parser.add_argument("net", nargs="?", type=str, help="Filter packets by network (e.g., 192.168.1.0/24)")

    # Parse arguments
    args = parser.parse_args()

    # Run packet analyzer with the provided arguments
    pktsniffer(args.pcap_file, host=args.host, port=args.port, ip=args.ip, tcp=args.tcp, udp=args.udp, icmp=args.icmp,
               net=args.net)


if __name__ == "__main__":
    # Specify the path to your .pcap file
    pcap_file = "C:\\Users\\Kyle\\Downloads\\test.pcap"
    main()
