import socket

HOST = '127.0.0.1'
PORT = 10000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen()
conn, addr = s.accept()
conn.setsockopt(socket.SOL_TCP, 31, "comp".encode())
with conn:
    while True:
        data = conn.recv(1024)
        if not data: break
        print(str(len(data.decode())) + ' bytes received')
        print(data.decode())
