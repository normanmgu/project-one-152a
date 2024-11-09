import dpkt
import socket
import sys

def analyze_activity(pcap_file):
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            # Data structure to hold details
            packet_lengths = []
            sources = set()
            destinations = set()
            other_protocol_counts = {}

            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                
                # Only process IP packets
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    # Record source and destination IPs
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    sources.add(src_ip)
                    destinations.add(dst_ip)

                    # Record packet length
                    packet_lengths.append(len(ip))

                    # Count protocols other than IP
                    proto = ip.p
                    other_protocol_counts[proto] = other_protocol_counts.get(proto, 0) + 1

            # Return results as a dictionary
            return {
                "file": pcap_file,
                "packet_lengths": packet_lengths,
                "sources": sources,
                "destinations": destinations,
                "other_protocol_counts": other_protocol_counts
            }

    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def compare_activities(activity1, activity2):
    # Compare packet lengths
    length_diff = sum(activity1["packet_lengths"]) - sum(activity2["packet_lengths"])
    
    # Compare sources and destinations
    source_diff = activity1["sources"].difference(activity2["sources"])
    destination_diff = activity1["destinations"].difference(activity2["destinations"])

    # Output comparison results
    print(f"Comparison between {activity1['file']} and {activity2['file']}:")
    print(f"Difference in total data length: {length_diff} bytes")
    print(f"Unique sources in {activity1['file']} not in {activity2['file']}: {source_diff}")
    print(f"Unique destinations in {activity1['file']} not in {activity2['file']}: {destination_diff}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Please specify two pcap files for comparison!")
    else:
        activity1 = analyze_activity(sys.argv[1])
        activity2 = analyze_activity(sys.argv[2])
        
        if activity1 and activity2:
            compare_activities(activity1, activity2)
