# Lab 6 Q3 - Client (DH with Signatures)
import socket
import random
import hashlib
import time

# DH parameters
p = 23
g = 5

def compute_shared_secret(private, other_public):
    return pow(other_public, private, p)

def sign_message(message, private_key):
    sign_key = hashlib.sha256(str(private_key).encode()).hexdigest()[:16]
    return hashlib.sha256((message + sign_key).encode()).hexdigest()[:32]

def verify_signature(message, signature, public_key):
    verify_key = hashlib.sha256(str(public_key).encode()).hexdigest()[:16]
    expected = hashlib.sha256((message + verify_key).encode()).hexdigest()[:32]
    return signature == expected

time.sleep(1)  # Wait for server

# Client setup
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 9999))
print("CLIENT: Connected to server")

# Generate client keys
client_private = random.randint(1, p-2)
client_public = pow(g, client_private, p)
print(f"CLIENT: My public key: {client_public}")

# Send public key to server
client.send(str(client_public).encode())

# Receive server's public key
server_pub = int(client.recv(1024).decode())
print(f"CLIENT: Server public key: {server_pub}")

# Compute shared secret
shared = compute_shared_secret(client_private, server_pub)
print(f"CLIENT: Shared secret: {shared}")

# Send signed message
client_msg = "Hello from Client"
client_sig = sign_message(client_msg, client_private)
client.send(client_msg.encode())

# Receive server's signed response
response = client.recv(1024).decode()
server_msg, server_sig = response.split('|')
print(f"CLIENT: Server message: {server_msg}")
print(f"CLIENT: Server signature: {server_sig[:16]}...")

# Verify server signature
valid = verify_signature(server_msg, server_sig, server_pub)
print(f"CLIENT: Signature valid: {valid}")

client.close()