import dpkt
import sys
import socket
from datetime import datetime

def parse_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            protocol_count = {}
            http_count = 0
            https_count = 0
            dest_ips = {}

            for timestamp, data in pcap:
                eth = dpkt.ethernet.Ethernet(data)

                # Skip if no IP layer data (IPv4 or IPv6)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                
                ip = eth.data
                dest_ip = socket.inet_ntoa(ip.dst)
                protocol = None
                ts = datetime.utcfromtimestamp(timestamp)

                # Track the destination IP and timestamp
                if dest_ip not in dest_ips:
                    dest_ips[dest_ip] = []
                dest_ips[dest_ip].append(ts)

                # TCP Layer Check
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    # Check for HTTP/HTTPS
                    if tcp.dport == 80 or tcp.sport == 80:
                        try:
                            if tcp.dport == 80:
                                http = dpkt.http.Request(tcp.data)
                            elif tcp.sport == 80:
                                http = dpkt.http.Response(tcp.data)
                            print("HTTP Headers:", http.headers)
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            pass
                        protocol = "HTTP"
                        http_count += 1
                    elif tcp.dport == 443 or tcp.sport == 443:
                        protocol = "HTTPS"
                        https_count += 1
                    elif tcp.dport == 21 or tcp.sport == 21:
                        protocol = "FTP"
                    elif tcp.dport == 22 or tcp.sport == 22:
                        protocol = "SSH"

                # Count protocols
                if protocol:
                    protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

            # Output Results
            print(f"Results for {pcap_file}:")
            print("Protocol counts:", protocol_count)
            print(f"HTTP packets for {pcap_file}: {http_count}")
            print(f"HTTPS packets for {pcap_file}: {https_count}")
            print("\nDestination IP addresses and timestamps:")
            for ip, times in dest_ips.items():
                print(f"{ip}: {[time.strftime('%Y-%m-%d %H:%M:%S') for time in times]}")
            print("-" * 50)

    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Please specify two pcap files!")
    else:
        parse_pcap(sys.argv[1])
        parse_pcap(sys.argv[2])
