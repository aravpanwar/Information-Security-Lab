# Lab 5 Q2 - Hash Server
import socket
import hashlib


def custom_hash(data):
    h = 5381
    for byte in data:
        h = (h * 33 + byte) & 0xFFFFFFFF
    return h


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 12345))
server.listen(1)
print("Server listening on port 12345...")

while True:
    conn, addr = server.accept()
    print(f"Connected to {addr}")

    data = conn.recv(1024)
    if not data:
        break

    print(f"Received: {data.decode()}")

    # Compute hash
    hash_value = custom_hash(data)
    print(f"Computed hash: {hash_value}")

    # Send hash back
    conn.send(str(hash_value).encode())
    conn.close()