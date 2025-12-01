# Lab 5 Q2 - Hash Client
import socket
import hashlib

def custom_hash(data):
    h = 5381
    for byte in data:
        h = (h * 33 + byte) & 0xFFFFFFFF
    return h

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 12345))

# Test 1: Normal transmission
message = b"Secure Data Transmission Test"
print(f"Sending: {message.decode()}")
client.send(message)

hash_received = client.recv(1024).decode()
hash_local = custom_hash(message)

print(f"Received hash: {hash_received}")
print(f"Local hash: {hash_local}")
print(f"Integrity check: {'PASS' if hash_received == str(hash_local) else 'FAIL'}")

client.close()

# Test 2: Simulate corruption
print("\n--- Simulating Corruption ---")
corrupt_message = b"Secure Data Transmissi0n Test"  # Changed 'o' to '0'
print(f"Corrupted message: {corrupt_message.decode()}")

client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client2.connect(('localhost', 12345))
client2.send(corrupt_message)
hash_received2 = client2.recv(1024).decode()
hash_local2 = custom_hash(corrupt_message)

print(f"Received hash: {hash_received2}")
print(f"Local hash: {hash_local2}")
print(f"Integrity check: {'PASS' if hash_received2 == str(hash_local2) else 'FAIL'}")
client2.close()