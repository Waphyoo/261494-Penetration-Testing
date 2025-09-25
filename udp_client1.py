import socket
import sys
from time import sleep

IP="127.0.0.1"
PORT=9090
data="Hello, UDP Server!"

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.sendto(data.encode(), (IP, PORT))
# sleep(1)  # Wait for a second to ensure the message is sent
# socket.sendto(b"exit", (IP, PORT))  # Send exit command to close the server
