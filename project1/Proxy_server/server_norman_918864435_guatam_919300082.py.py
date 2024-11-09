import socket
import json

def run_server(host, port):

  server_address = (host, port)
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

    server_socket.bind(server_address)
    server_socket.listen(1) # just
    print(f"Server listening on port {port}")
    
    while True: # make server run indefinately

      try:
        #(<socket.socket fd=4, family=2, type=1, proto=0, laddr=('127.0.0.1', 5500), raddr=('127.0.0.1', 53956)>, ('127.0.0.1', 53956))V
        proxy_socket, proxy_address = server_socket.accept()
        data = proxy_socket.recv(1024)
        print(data.decode())
        message = "pong"
        proxy_socket.send(message.encode())
      except Exception as e:
        print(f"Error handling request {e}")
      finally:
        proxy_socket.close()

def main():
  HOST = '127.0.0.1'
  PORT = 3000
  run_server(HOST, PORT)

main()