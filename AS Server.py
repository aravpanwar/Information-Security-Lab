# auth_server.py
import socket
import hashlib
import json
import secrets
from datetime import datetime, timedelta


class AuthServer:
    def __init__(self, host='127.0.0.1', port=5557):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)

        # User database (username: hashed_password)
        self.users = {
            'alice': self.hash_password('alice123'),
            'bob': self.hash_password('bob123'),
            'charlie': self.hash_password('charlie123')
        }

        # Active sessions (token: username)
        self.sessions = {}

        print(f"🔐 Authentication Server started on {host}:{port}")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def generate_token(self, username):
        token = secrets.token_hex(32)
        expiry = datetime.now() + timedelta(hours=1)
        self.sessions[token] = {
            'username': username,
            'expiry': expiry.isoformat()
        }
        return token

    def validate_token(self, token):
        if token in self.sessions:
            expiry = datetime.fromisoformat(self.sessions[token]['expiry'])
            if datetime.now() < expiry:
                return self.sessions[token]['username']
        return None

    def handle_client(self, client_socket):
        try:
            while True:
                request = client_socket.recv(1024).decode()
                if not request:
                    break

                data = json.loads(request)
                action = data.get('action')

                if action == 'register':
                    username = data['username']
                    password = data['password']

                    if username in self.users:
                        response = {'status': 'error', 'message': 'User exists'}
                    else:
                        self.users[username] = self.hash_password(password)
                        response = {'status': 'success', 'message': 'Registered'}

                elif action == 'login':
                    username = data['username']
                    password = data['password']

                    if username in self.users and self.users[username] == self.hash_password(password):
                        token = self.generate_token(username)
                        response = {
                            'status': 'success',
                            'token': token,
                            'message': 'Login successful'
                        }
                    else:
                        response = {'status': 'error', 'message': 'Invalid credentials'}

                elif action == 'access':
                    token = data.get('token')
                    resource = data.get('resource')

                    username = self.validate_token(token)
                    if username:
                        response = {
                            'status': 'success',
                            'message': f'Access granted to {resource}',
                            'user': username
                        }
                    else:
                        response = {'status': 'error', 'message': 'Invalid token'}

                elif action == 'logout':
                    token = data.get('token')
                    if token in self.sessions:
                        del self.sessions[token]
                    response = {'status': 'success', 'message': 'Logged out'}

                else:
                    response = {'status': 'error', 'message': 'Invalid action'}

                client_socket.send(json.dumps(response).encode())

        except:
            pass
        finally:
            client_socket.close()

    def start(self):
        print(f"👥 Registered users: {list(self.users.keys())}")

        while True:
            client_socket, address = self.server.accept()
            print(f"\n📡 Connection from {address}")

            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            )
            client_thread.start()


if __name__ == "__main__":
    import threading

    server = AuthServer()
    server.start()