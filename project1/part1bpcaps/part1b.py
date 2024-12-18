import dpkt
import sys

def parse_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, data in pcap:
                eth = dpkt.ethernet.Ethernet(data)

                # Skip if no IP layer data (IPv4 or IPv6)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                ip = eth.data

                # TCP Layer Check
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    # Check for HTTP/HTTPS
                    if tcp.dport == 80 or tcp.sport == 80:
                        try:
                            if tcp.dport == 80:
                                http = dpkt.http.Request(tcp.data)
                                print("GET URL:", http.uri)
                                print("HTTP Headers:", http.headers)
                                print("HTTP Payload:", http.body)
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            pass
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