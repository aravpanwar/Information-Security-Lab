# file_client.py
import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64


class SecureFileClient:
    def __init__(self, host='127.0.0.1', port=5556):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))

        # Receive server's public key
        public_key_data = self.client.recv(2048)
        self.server_public_key = RSA.import_key(public_key_data)

        print(f"Connected to server")
        print(f"Server Public Key received")

    def encrypt_file(self, filename):
        # Generate AES key for this file
        aes_key = get_random_bytes(16)

        # Read file
        with open(filename, 'rb') as f:
            file_data = f.read()

        # Calculate MD5 hash for integrity
        file_hash = hashlib.md5(file_data).digest()

        # Encrypt with AES
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Pad data
        pad_length = 16 - (len(file_data) % 16)
        file_data += bytes([pad_length]) * pad_length

        ciphertext = cipher.encrypt(file_data)

        # Combine IV + ciphertext + hash
        encrypted_data = iv + ciphertext + file_hash
        encrypted_b64 = base64.b64encode(encrypted_data).decode()

        # Encrypt AES key with server's RSA public key
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        return encrypted_b64, encrypted_aes_key

    def send_file(self, filename):
        try:
            print(f"📤 Sending {filename}...")

            # Encrypt file
            encrypted_file, encrypted_key = self.encrypt_file(filename)

            # Send encrypted AES key
            self.client.send(encrypted_key)

            # Send encrypted file
            self.client.send(encrypted_file.encode())

            # Send filename
            self.client.send(filename.encode())

            # Get response
            response = self.client.recv(1024).decode()
            print(f"📥 Server response: {response}")

        except FileNotFoundError:
            print(f"❌ File {filename} not found!")
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    client = SecureFileClient()

    while True:
        print("\n1. Send file")
        print("2. Exit")
        choice = input("Select: ")

        if choice == '1':
            filename = input("Enter filename to send: ")
            client.send_file(filename)
        elif choice == '2':
            client.client.close()
            print("👋 Goodbye!")
            break