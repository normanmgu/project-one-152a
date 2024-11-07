# Create large payload (100MB of arbitrary data)
# Record start time
# Send data using UDP (considering UDP limitations, will need to chunk it)
# Wait for throughput response from server
# Print received throughput
import socket
import sys

# specify server host and port to connect to
sizes_to_test = [
    1472,    # Safe size
    4096,    # 4KB
    8192,    # 8KB
    16384,   # 16KB
    32768,   # 32KB
    65507    # Max theoretical
]

def iperf_send(data, host, port):
  chunk_size = 1472
  num_chunks = len(data) // chunk_size

  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(b"START", (host, port))

    for i in range(num_chunks):
      start_idx = i * chunk_size
      end_idx = start_idx + chunk_size
      chunk = data[start_idx:end_idx]
      try:
        sock.sendto(chunk, (host, port))
      except Exception as e:
        print("Failed to send bytes: {e}")

    # Send any remaining data
    if len(data) % chunk_size != 0:
        last_chunk = data[num_chunks * chunk_size:]
        sock.sendto(last_chunk, (host, port))

    sock.sendto(b"END", (host, port))


def main():
  SERVER_HOST = '127.0.0.1'
  SERVER_PORT = 5500

  data = b'x' * (100 * 1024 * 1024) # 100 megabyte string

  iperf_send(data, SERVER_HOST, SERVER_PORT)

main() 
