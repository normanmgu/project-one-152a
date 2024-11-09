import dpkt
import sys

def parse_pcap(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            protocol_count = {}
            browser_count = {}

            for timestamp, data in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(data)
                except dpkt.UnpackError:
                    # Skip non-Ethernet packets
                    continue

                # Skip if no IP layer data (IPv4 or IPv6)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                
                ip = eth.data
                protocol = None

                # TCP Layer Check
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    # Check for common application layer protocols
                    if tcp.dport == 80 or tcp.sport == 80:
                        protocol = "HTTP"
                        # Attempt to parse HTTP requests for User-Agent
                        try:
                            http = dpkt.http.Request(tcp.data)
                            user_agent = http.headers.get("user-agent", "")
                            browser = "Unknown Browser"
                            
                            if "Chrome" in user_agent and "Chromium" not in user_agent:
                                browser = "Google Chrome"
                            elif "Firefox" in user_agent:
                                browser = "Mozilla Firefox"
                            elif "Safari" in user_agent and "Chrome" not in user_agent:
                                browser = "Safari"
                            elif "Edge" in user_agent:
                                browser = "Microsoft Edge"
                            elif "Trident" in user_agent or "MSIE" in user_agent:
                                browser = "Internet Explorer"

                            # Count the detected browser
                            browser_count[browser] = browser_count.get(browser, 0) + 1
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            pass  # Skip malformed HTTP packets
                        
                    elif tcp.dport == 443 or tcp.sport == 443:
                        protocol = "HTTPS"
                    elif tcp.dport == 21 or tcp.sport == 21:
                        protocol = "FTP"
                    elif tcp.dport == 22 or tcp.sport == 22:
                        protocol = "SSH"
                    elif tcp.dport == 25 or tcp.sport == 25:
                        protocol = "SMTP"
                    elif tcp.dport == 110 or tcp.sport == 110 or tcp.dport == 995 or tcp.sport == 995:
                        protocol = "POP3"

                # UDP Layer Check for DNS
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    if udp.dport == 53 or udp.sport == 53:
                        protocol = "DNS"

                # ICMP Layer Check
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    protocol = "ICMP"

                # Count only recognized protocols
                if protocol:
                    protocol_count[protocol] = protocol_count.get(protocol, 0) + 1

            # Output Results
            print(f"\nResults for {pcap_file}")
            print("Application layer protocol counts:", protocol_count)
            print("Browser counts:", browser_count)

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
