import socket
import json
    
def tcp_send(data, server, port):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        
        client_socket.connect((server, port))
        print("Handshake established with proxy")

        client_socket.send(data)
        proxy_data = client_socket.recv(1024)
        message = proxy_data.decode()
        print(message)

def main():
    PROXY_HOST = '127.0.0.1'
    PROXY_PORT = 5500

    data = {
        "server_ip": "127.0.0.1", # The server's IP (destination)
        "server_port": 3000, # The server's port (destination)
        "message": "ping" # The actual message
    }

    # Data with blocked ip
    # data =  {
    #     "server_ip": "246.182.24.10", # The server's IP (destination)
    #     "server_port": 3000, # The server's port (destination)
    #     "message": "ping" # The actual message
    # }

    json_data = json.dumps(data).encode()

    tcp_send(json_data, PROXY_HOST, PROXY_PORT)


main()
    