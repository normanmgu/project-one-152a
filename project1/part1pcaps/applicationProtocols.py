import dpkt
import sys

def parse_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            protocol_count = {}

            for timestamp, data in pcap:
                eth = dpkt.ethernet.Ethernet(data)

                # Skip if no IP layer data (IPv4 or IPv6)
                if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
                    continue
                
                ip = eth.data
                protocol = None

                # TCP Layer Check
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    # Check for HTTP/HTTPS/FTP/SSH protocols
                    if tcp.dport == 80 or tcp.sport == 80:
                        protocol = "HTTP"
                    elif tcp.dport == 443 or tcp.sport == 443:
                        protocol = "HTTPS"
                    elif tcp.dport == 21 or tcp.sport == 21:
                        protocol = "FTP"
                    elif tcp.dport == 22 or tcp.sport == 22:
                        protocol = "SSH"

                # UDP Layer Check for DNS
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    if udp.dport == 53 or udp.sport == 53:
                        protocol = "DNS"

                # Count only application layer protocols
                if protocol:
                    protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

            # Output Results
            print(f"\nResults for {pcap_file}")
            print("Application layer protocol counts:", protocol_count)

    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap files specified!")
    else:
        for pcap_file in sys.argv[1:]:
            parse_pcap(pcap_file)
