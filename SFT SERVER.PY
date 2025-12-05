# file_server.py
import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64


class SecureFileServer:
    def __init__(self, host='127.0.0.1', port=5556):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(1)

        # Generate RSA keys
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

        print(f"📁 Secure File Server started on {host}:{port}")
        print(f"Public Key:\n{self.public_key.export_key().decode()[:50]}...")

    def decrypt_aes_key(self, encrypted_key):
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(encrypted_key)

    def decrypt_file(self, encrypted_data, aes_key):
        data = base64.b64decode(encrypted_data)
        iv = data[:16]
        ciphertext = data[16:-16]
        received_hash = data[-16:]

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Verify integrity
        calculated_hash = hashlib.md5(plaintext).digest()
        integrity_ok = received_hash == calculated_hash

        return plaintext, integrity_ok

    def start(self):
        while True:
            client_socket, address = self.server.accept()
            print(f"\n📡 Connection from {address}")

            try:
                # Send public key to client
                client_socket.send(self.public_key.export_key())

                # Receive encrypted AES key
                encrypted_aes_key = client_socket.recv(1024)
                aes_key = self.decrypt_aes_key(encrypted_aes_key)
                print(f"AES Key decrypted: {aes_key.hex()[:20]}...")

                # Receive encrypted file
                encrypted_file = client_socket.recv(4096).decode()
                filename = client_socket.recv(1024).decode()

                # Decrypt file
                plaintext, integrity_ok = self.decrypt_file(encrypted_file, aes_key)

                # Save file
                with open(f"received_{filename}", 'wb') as f:
                    f.write(plaintext)

                print(f"✅ File saved: received_{filename}")
                print(f"🔍 Integrity: {'✅ OK' if integrity_ok else '❌ FAILED'}")
                print(f"📊 Size: {len(plaintext)} bytes")

                # Send confirmation
                if integrity_ok:
                    client_socket.send(b"File received with integrity verified!")
                else:
                    client_socket.send(b"File received but integrity check failed!")

            except Exception as e:
                print(f"❌ Error: {e}")
            finally:
                client_socket.close()


if __name__ == "__main__":
    server = SecureFileServer()
    server.start()