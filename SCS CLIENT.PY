# chat_client.py
import socket
import threading
import json
from Crypto.Cipher import AES
import base64


class SecureChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))

        # Receive AES key from server
        self.aes_key = self.client.recv(16)
        print(f"✅ Connected to server. AES Key received.")

        self.running = True

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

    def receive_messages(self):
        while self.running:
            try:
                encrypted_json = self.client.recv(1024).decode()
                if encrypted_json:
                    message = self.decrypt_message(encrypted_json)
                    print(f"\n[Server] {message}\nYou: ", end='')
            except:
                break

    def start(self):
        # Start receiving thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

        print("Type your messages (type 'exit' to quit):")

        while self.running:
            message = input("You: ")
            if message.lower() == 'exit':
                self.running = False
                self.client.close()
                break

            # Encrypt and send
            encrypted = self.encrypt_message(message)
            self.client.send(encrypted.encode())


if __name__ == "__main__":
    client = SecureChatClient()
    client.start()