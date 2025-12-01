# Lab 6 Q3 - Server (DH with Signatures)
import socket
import random
import hashlib

# DH parameters
p = 23  # Small prime for demo
g = 5

def compute_shared_secret(private, other_public):
    return pow(other_public, private, p)

def sign_message(message, private_key):
    sign_key = hashlib.sha256(str(private_key).encode()).hexdigest()[:16]
    return hashlib.sha256((message + sign_key).encode()).hexdigest()[:32]

# Server setup
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 9999))
server.listen(1)
print("SERVER: Waiting for connection...")

conn, addr = server.accept()
print(f"SERVER: Connected to {addr}")

# Receive client's public key
client_pub = int(conn.recv(1024).decode())
print(f"SERVER: Client public key: {client_pub}")

# Generate server keys
server_private = random.randint(1, p-2)
server_public = pow(g, server_private, p)
print(f"SERVER: My public key: {server_public}")

# Send server public key
conn.send(str(server_public).encode())

# Compute shared secret
shared = compute_shared_secret(server_private, client_pub)
print(f"SERVER: Shared secret: {shared}")

# Receive client's signed message
client_msg = conn.recv(1024).decode()
print(f"SERVER: Received message: {client_msg}")

# Sign acknowledgment
server_msg = "ACK - SERVER"
server_sig = sign_message(server_msg, server_private)

# Send signed response
conn.send(f"{server_msg}|{server_sig}".encode())

print("SERVER: Sent signed response")
conn.close()