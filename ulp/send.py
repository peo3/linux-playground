import sys
import socket

size = int(sys.argv[1])

HOST = '127.0.0.1'
PORT = 10000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
s.setsockopt(socket.SOL_TCP, 31, "comp".encode())
s.connect((HOST, PORT))
msg = 'a' * size
s.send(msg.encode())
print(str(len(msg.encode())) + ' bytes sent')
print(msg)
