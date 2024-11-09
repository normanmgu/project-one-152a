import socket
import json

def run_proxy(host, port, block_list):

  proxy_address = (host, port)
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:

    proxy_socket.bind(proxy_address)
    proxy_socket.listen(1) # just
    print(f"Listening on port {port}")

    while True:
      try:

        client_socket, client_address = proxy_socket.accept()
        print(f"Connected to {client_address}")

        client_data = client_socket.recv(1024)
        json_data = json.loads(client_data.decode())
        server_address = (json_data["server_ip"], json_data["server_port"])
        message: str = json_data["message"]

        server_ip, _ = server_address
        if server_ip in block_list:
          error_message = f"Error: IP ${server_address} blocked"
          client_socket.send(error_message.encode())
          raise Exception(error_message)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
          server_socket.connect((server_address))
          server_socket.send(message.encode())
          server_data = server_socket.recv(1024)

          server_message = server_data.decode()
          server_socket.close()

        client_socket.send(server_message.encode())

      except Exception as e:
        print(f"Error handling request {e}")

      finally:
        client_socket.close()


def main():
  HOST = '127.0.0.1'
  PORT = 5500
  BLOCK_LIST = ["48.179.207.143", "246.182.24.10", "162.29.73.16"]

  run_proxy(HOST, PORT, BLOCK_LIST)

main()