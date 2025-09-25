import socket

IP="127.0.0.1"
PORT=9090

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind((IP, PORT))

while True:
    data, addr = socket.recvfrom(1024)  # Buffer size is 1024 bytes
    if data.decode() == "exit":
        print("Exit command received. Shutting down server.")
        break
    print(f"Received message: {data.decode()} from {addr}")