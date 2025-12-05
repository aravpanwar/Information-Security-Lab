# chat_server.py
import socket
import threading
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


class SecureChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()

        self.clients = {}
        self.aes_key = get_random_bytes(16)  # Shared AES key for demo

        print(f"🔐 Secure Chat Server started on {host}:{port}")
        print(f"AES Key: {self.aes_key.hex()}")

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        encrypted_data = {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode()
        }
        return json.dumps(encrypted_data)

    def decrypt_message(self, encrypted_json):
        data = json.loads(encrypted_json)
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        tag = base64.b64decode(data['tag'])

        cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()

    def handle_client(self, client_socket, address):
        print(f"📡 New connection from {address}")

        # Send AES key to client (in real system, use proper key exchange)
        client_socket.send(self.aes_key)

        while True:
            try:
                # Receive encrypted message
                encrypted_json = client_socket.recv(1024).decode()
                if not encrypted_json:
                    break

                # Decrypt and process
                message = self.decrypt_message(encrypted_json)
                print(f"[{address}] {message}")

                # Broadcast to all clients
                broadcast_msg = self.encrypt_message(f"[{address[1]}] {message}")
                for sock in self.clients.values():
                    sock.send(broadcast_msg.encode())

            except:
                break

        # Client disconnected
        del self.clients[address]
        client_socket.close()
        print(f"❌ {address} disconnected")

    def start(self):
        while True:
            client_socket, address = self.server.accept()
            self.clients[address] = client_socket

            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, address)
            )
            client_thread.start()


if __name__ == "__main__":
    server = SecureChatServer()
    server.start()