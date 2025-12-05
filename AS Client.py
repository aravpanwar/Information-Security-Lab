# auth_client.py
import socket
import json


class AuthClient:
    def __init__(self, host='127.0.0.1', port=5557):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.token = None
        print(f"✅ Connected to auth server")

    def send_request(self, action, **kwargs):
        request = {'action': action, **kwargs}
        self.client.send(json.dumps(request).encode())
        response = self.client.recv(1024).decode()
        return json.loads(response)

    def register(self):
        username = input("Username: ")
        password = input("Password: ")
        response = self.send_request('register', username=username, password=password)
        print(f"Server: {response['message']}")

    def login(self):
        username = input("Username: ")
        password = input("Password: ")
        response = self.send_request('login', username=username, password=password)

        if response['status'] == 'success':
            self.token = response['token']
            print(f"✅ Login successful!")
            print(f"Token: {self.token[:20]}...")
        else:
            print(f"❌ {response['message']}")

    def access_resource(self):
        if not self.token:
            print("❌ Not logged in")
            return

        resource = input("Resource to access: ")
        response = self.send_request('access', token=self.token, resource=resource)

        if response['status'] == 'success':
            print(f"✅ {response['message']}")
            print(f"User: {response['user']}")
        else:
            print(f"❌ {response['message']}")

    def logout(self):
        if self.token:
            response = self.send_request('logout', token=self.token)
            self.token = None
            print(f"✅ {response['message']}")
        else:
            print("Not logged in")


if __name__ == "__main__":
    client = AuthClient()

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Access Resource")
        print("4. Logout")
        print("5. Exit")

        choice = input("Select: ")

        if choice == '1':
            client.register()
        elif choice == '2':
            client.login()
        elif choice == '3':
            client.access_resource()
        elif choice == '4':
            client.logout()
        elif choice == '5':
            client.client.close()
            print("👋 Goodbye!")
            break