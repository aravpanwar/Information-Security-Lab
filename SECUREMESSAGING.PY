# messaging_system.py
import hashlib
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class SecureMessagingSystem:
    def __init__(self):
        self.users = {
            'alice': {'password': self.hash('alice123'), 'public_key': None, 'private_key': None},
            'bob': {'password': self.hash('bob123'), 'public_key': None, 'private_key': None},
            'charlie': {'password': self.hash('charlie123'), 'public_key': None, 'private_key': None},
            'david': {'password': self.hash('david123'), 'public_key': None, 'private_key': None}
        }

        # Generate RSA keys for each user
        for user in self.users:
            key = RSA.generate(2048)
            self.users[user]['public_key'] = key.publickey()
            self.users[user]['private_key'] = key

        self.messages = []
        self.groups = {
            'team_alpha': ['alice', 'bob'],
            'team_beta': ['bob', 'charlie', 'david']
        }

        # Session keys for each conversation
        self.session_keys = {}
        self.current_user = None

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == self.hash(password):
            self.current_user = username
            return True
        return False

    def generate_session_key(self, recipient):
        """Generate and exchange session key for secure messaging"""
        session_id = f"{self.current_user}_{recipient}"
        reverse_id = f"{recipient}_{self.current_user}"

        # Check if session already exists
        if session_id in self.session_keys or reverse_id in self.session_keys:
            actual_id = session_id if session_id in self.session_keys else reverse_id
            return self.session_keys[actual_id]

        # Generate new session key
        session_key = get_random_bytes(32)

        # Encrypt session key with recipient's public key
        cipher = PKCS1_OAEP.new(self.users[recipient]['public_key'])
        encrypted_key = cipher.encrypt(session_key)

        # Store session key (both users share the same key)
        self.session_keys[session_id] = {
            'key': session_key,
            'encrypted_for_recipient': base64.b64encode(encrypted_key).decode(),
            'established': datetime.now().isoformat()
        }

        return self.session_keys[session_id]

    def encrypt_message(self, plaintext, session_key):
        """Encrypt message with AES using session key"""
        cipher = AES.new(session_key['key'], AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        iv = cipher.iv

        return {
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ct_bytes).decode(),
            'timestamp': datetime.now().isoformat()
        }

    def decrypt_message(self, encrypted_message, session_key):
        """Decrypt message with AES using session key"""
        iv = base64.b64decode(encrypted_message['iv'])
        ciphertext = base64.b64decode(encrypted_message['ciphertext'])

        cipher = AES.new(session_key['key'], AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext.decode()

    def send_message(self, recipient, message):
        """Send encrypted message to another user"""
        if recipient not in self.users:
            return "Recipient not found"

        # Generate or get session key
        session_key = self.generate_session_key(recipient)

        # Encrypt message
        encrypted = self.encrypt_message(message, session_key)

        # Store message
        msg_record = {
            'sender': self.current_user,
            'recipient': recipient,
            'encrypted': encrypted,
            'session_key_id': f"{self.current_user}_{recipient}",
            'delivered': False
        }

        self.messages.append(msg_record)

        return f"Message sent to {recipient}"

    def send_group_message(self, group_name, message):
        """Send encrypted message to a group"""
        if group_name not in self.groups:
            return "Group not found"

        if self.current_user not in self.groups[group_name]:
            return "You are not a member of this group"

        sent_count = 0
        for member in self.groups[group_name]:
            if member != self.current_user:
                self.send_message(member, f"[GROUP:{group_name}] {message}")
                sent_count += 1

        return f"Message sent to {sent_count} group members"

    def get_messages(self):
        """Get messages for current user"""
        user_messages = []

        for msg in self.messages:
            if msg['recipient'] == self.current_user and not msg['delivered']:
                # Decrypt message
                session_key_id = msg['session_key_id']
                reverse_id = f"{msg['recipient']}_{msg['sender']}"

                # Try both session key IDs
                session_key = None
                if session_key_id in self.session_keys:
                    session_key = self.session_keys[session_key_id]
                elif reverse_id in self.session_keys:
                    session_key = self.session_keys[reverse_id]

                if session_key:
                    decrypted = self.decrypt_message(msg['encrypted'], session_key)

                    user_messages.append({
                        'sender': msg['sender'],
                        'message': decrypted,
                        'timestamp': msg['encrypted']['timestamp']
                    })

                    # Mark as delivered
                    msg['delivered'] = True

        return user_messages

    def get_conversation(self, other_user):
        """Get conversation history with another user"""
        conversation = []

        for msg in self.messages:
            if ((msg['sender'] == self.current_user and msg['recipient'] == other_user) or
                    (msg['sender'] == other_user and msg['recipient'] == self.current_user)):

                # Try to decrypt
                session_key_id = msg['session_key_id']
                reverse_id = f"{msg['recipient']}_{msg['sender']}"

                session_key = None
                if session_key_id in self.session_keys:
                    session_key = self.session_keys[session_key_id]
                elif reverse_id in self.session_keys:
                    session_key = self.session_keys[reverse_id]

                if session_key and 'encrypted' in msg:
                    try:
                        decrypted = self.decrypt_message(msg['encrypted'], session_key)

                        conversation.append({
                            'sender': msg['sender'],
                            'message': decrypted,
                            'timestamp': msg['encrypted']['timestamp'],
                            'encrypted': False
                        })
                    except:
                        conversation.append({
                            'sender': msg['sender'],
                            'message': '[ENCRYPTED - CANNOT DECRYPT]',
                            'timestamp': msg['encrypted']['timestamp'],
                            'encrypted': True
                        })
                else:
                    conversation.append({
                        'sender': msg['sender'],
                        'message': '[ENCRYPTED - NO KEY]',
                        'timestamp': msg.get('encrypted', {}).get('timestamp', 'N/A'),
                        'encrypted': True
                    })

        return sorted(conversation, key=lambda x: x['timestamp'])

    def create_group(self, group_name, members):
        """Create a new group"""
        if group_name in self.groups:
            return "Group already exists"

        # Add current user to members if not included
        if self.current_user not in members:
            members.append(self.current_user)

        # Validate members
        valid_members = []
        for member in members:
            if member in self.users:
                valid_members.append(member)

        if len(valid_members) < 2:
            return "Group must have at least 2 members"

        self.groups[group_name] = valid_members
        return f"Group '{group_name}' created with {len(valid_members)} members"


def main():
    messenger = SecureMessagingSystem()

    print("💬 SECURE MESSAGING SYSTEM")
    print("=" * 50)
    print("Users: alice, bob, charlie, david")
    print("Passwords: alice123, bob123, charlie123, david123")
    print("Groups: team_alpha (alice, bob), team_beta (bob, charlie, david)")

    # Login
    while True:
        print("\n🔐 Login")
        user = input("Username: ")
        pwd = input("Password: ")

        if messenger.login(user, pwd):
            print(f"✅ Welcome, {user}!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        print(f"\n👤 {messenger.current_user}")
        print("\n1. Send Private Message")
        print("2. Send Group Message")
        print("3. Check Messages")
        print("4. View Conversation")
        print("5. Create Group")
        print("6. Show Groups")
        print("7. Show Session Keys")
        print("8. Exit")

        choice = input("\nSelect option: ")

        if choice == '1':
            print("\n📤 SEND PRIVATE MESSAGE")
            print("Available users: " + ", ".join([u for u in messenger.users.keys() if u != messenger.current_user]))
            recipient = input("To: ")
            message = input("Message: ")
            result = messenger.send_message(recipient, message)
            print(result)

        elif choice == '2':
            print("\n👥 SEND GROUP MESSAGE")
            print("Your groups: " + ", ".join(
                [g for g in messenger.groups.keys() if messenger.current_user in messenger.groups[g]]))
            group = input("Group: ")
            message = input("Message: ")
            result = messenger.send_group_message(group, message)
            print(result)

        elif choice == '3':
            print("\n📥 CHECK MESSAGES")
            messages = messenger.get_messages()
            if messages:
                for msg in messages:
                    print(f"\n[{msg['timestamp'][:19]}] From {msg['sender']}:")
                    print(f"  {msg['message']}")
            else:
                print("No new messages")

        elif choice == '4':
            print("\n💭 VIEW CONVERSATION")
            other = input("Other user: ")
            conversation = messenger.get_conversation(other)

            if conversation:
                print(f"\n💬 Conversation with {other}:")
                for msg in conversation:
                    prefix = "You: " if msg['sender'] == messenger.current_user else f"{msg['sender']}: "
                    timestamp = msg['timestamp'][:19]
                    print(f"\n[{timestamp}] {prefix}{msg['message']}")
                    if msg['encrypted']:
                        print("  🔐 (Encrypted)")
            else:
                print(f"No conversation with {other}")

        elif choice == '5':
            print("\n➕ CREATE GROUP")
            group_name = input("Group name: ")
            print("Available users: " + ", ".join([u for u in messenger.users.keys() if u != messenger.current_user]))
            members_input = input("Members (comma-separated): ")
            members = [m.strip() for m in members_input.split(',')]
            result = messenger.create_group(group_name, members)
            print(result)

        elif choice == '6':
            print("\n👥 YOUR GROUPS:")
            for group_name, members in messenger.groups.items():
                if messenger.current_user in members:
                    print(f"\n{group_name}:")
                    for member in members:
                        prefix = "• " if member == messenger.current_user else "  "
                        print(f"{prefix}{member}")

        elif choice == '7':
            print("\n🔑 ACTIVE SESSION KEYS:")
            for key_id, key_data in messenger.session_keys.items():
                if messenger.current_user in key_id:
                    other_user = key_id.replace(f"{messenger.current_user}_", "").replace(f"_{messenger.current_user}",
                                                                                          "")
                    print(f"\nWith {other_user}:")
                    print(f"  Established: {key_data['established'][:19]}")
                    print(f"  Key (first 16 chars): {key_data['key'].hex()[:16]}...")

        elif choice == '8':
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    main()