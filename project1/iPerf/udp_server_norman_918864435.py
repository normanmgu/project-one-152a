import socket
import time

def iperf_receive(host, port):
    # Track received data and timing
    total_bytes = 0
    start_time = None
    received_chunks = {}
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"Server listening on {host}:{port}")
        
        while True:
            data, client_addr = sock.recvfrom(2000)  # Buffer slightly larger than chunk size
            
            # Handle start message
            if data.startswith(b"START"):
                start_time = time.time()
                print("Starting transfer...")
                continue
                
            # Handle end message
            if data == b"END":
                end_time = time.time()
                duration = end_time - start_time
                
                # Calculate throughput (KB/s)
                throughput = (total_bytes / 1024) / duration  # Convert bytes to KB
                
                # Send throughput back to client
                sock.sendto(str(throughput).encode(), client_addr)
                print(f"\nTransfer complete:")
                print(f"Total bytes: {total_bytes}")
                print(f"Time taken: {duration:.2f} seconds")
                print(f"Throughput: {throughput:.2f} KB/s")
                break
                
            # Handle regular data chunks
            total_bytes += len(data)
            
            # Optional: Print progress every megabyte
            if total_bytes % (1024 * 1024) == 0:
                print(f"Received {total_bytes / (1024 * 1024):.0f} MB...")

def main():
    HOST = '127.0.0.1'
    PORT = 5500
    iperf_receive(HOST, PORT)

main()