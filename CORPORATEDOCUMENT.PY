# document_system.py
# Features: Employees, managers, RSA signatures, document encryption
import hashlib
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class DocumentManagementSystem:
    def __init__(self):
        self.documents = {}
        self.document_counter = 1

        self.users = {
            'employee1': {'password': self.hash('emp123'), 'role': 'employee', 'dept': 'HR'},
            'employee2': {'password': self.hash('emp456'), 'role': 'employee', 'dept': 'Finance'},
            'manager1': {'password': self.hash('mgr123'), 'role': 'manager', 'dept': 'HR'},
            'manager2': {'password': self.hash('mgr456'), 'role': 'manager', 'dept': 'Finance'},
            'director': {'password': self.hash('dir123'), 'role': 'director', 'dept': 'Executive'}
        }

        # Generate RSA keys for each user
        self.user_keys = {}
        for user in self.users:
            key = RSA.generate(2048)
            self.user_keys[user] = {
                'private': key,
                'public': key.publickey()
            }

        self.current_user = None
        self.session_key = None

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == self.hash(password):
            self.current_user = username
            self.session_key = get_random_bytes(16)
            return True
        return False

    def encrypt_document(self, content, recipients):
        """Encrypt document with AES, then encrypt AES key with recipients' RSA keys"""
        # Generate document ID
        doc_id = f"DOC{self.document_counter:04d}"
        self.document_counter += 1

        # Generate document key
        doc_key = get_random_bytes(16)

        # Encrypt content with AES
        cipher = AES.new(doc_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(content.encode(), AES.block_size))
        iv = cipher.iv
        encrypted_content = base64.b64encode(iv + ct_bytes).decode()

        # Encrypt document key for each recipient
        encrypted_keys = {}
        for recipient in recipients:
            if recipient in self.user_keys:
                cipher_rsa = PKCS1_OAEP.new(self.user_keys[recipient]['public'])
                encrypted_keys[recipient] = base64.b64encode(
                    cipher_rsa.encrypt(doc_key)
                ).decode()

        # Create document record
        document = {
            'id': doc_id,
            'title': content[:50] + ('...' if len(content) > 50 else ''),
            'author': self.current_user,
            'dept': self.users[self.current_user]['dept'],
            'timestamp': datetime.now().isoformat(),
            'encrypted_content': encrypted_content,
            'encrypted_keys': encrypted_keys,
            'signatures': {},
            'access_log': []
        }

        self.documents[doc_id] = document
        self.log_access(doc_id, 'CREATED')

        return doc_id

    def sign_document(self, doc_id):
        """Digitally sign a document"""
        if doc_id not in self.documents:
            return "Document not found"

        doc = self.documents[doc_id]

        # Check permissions
        user_role = self.users[self.current_user]['role']
        user_dept = self.users[self.current_user]['dept']

        if user_role == 'employee' and doc['dept'] != user_dept:
            return "Cannot sign documents from other departments"

        # Create signature
        signature_data = {
            'doc_id': doc_id,
            'author': doc['author'],
            'timestamp': doc['timestamp']
        }

        h = SHA256.new(json.dumps(signature_data).encode())
        signature = pkcs1_15.new(self.user_keys[self.current_user]['private']).sign(h)

        # Store signature
        doc['signatures'][self.current_user] = {
            'signature': base64.b64encode(signature).decode(),
            'timestamp': datetime.now().isoformat(),
            'role': user_role
        }

        self.log_access(doc_id, 'SIGNED')
        return f"Document {doc_id} signed by {self.current_user}"

    def verify_signature(self, doc_id, signer):
        """Verify a digital signature"""
        if doc_id not in self.documents:
            return "Document not found"

        doc = self.documents[doc_id]

        if signer not in doc['signatures']:
            return f"No signature from {signer}"

        signature_data = {
            'doc_id': doc_id,
            'author': doc['author'],
            'timestamp': doc['timestamp']
        }

        h = SHA256.new(json.dumps(signature_data).encode())
        signature = base64.b64decode(doc['signatures'][signer]['signature'])

        try:
            pkcs1_15.new(self.user_keys[signer]['public']).verify(h, signature)
            return f"✅ Signature from {signer} is VALID"
        except:
            return f"❌ Signature from {signer} is INVALID"

    def decrypt_document(self, doc_id):
        """Decrypt and view document"""
        if doc_id not in self.documents:
            return "Document not found"

        doc = self.documents[doc_id]

        # Check if user has access
        if self.current_user not in doc['encrypted_keys']:
            return "Access denied"

        # Decrypt document key
        encrypted_key = base64.b64decode(doc['encrypted_keys'][self.current_user])
        cipher_rsa = PKCS1_OAEP.new(self.user_keys[self.current_user]['private'])
        doc_key = cipher_rsa.decrypt(encrypted_key)

        # Decrypt content
        encrypted_data = base64.b64decode(doc['encrypted_content'])
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]

        cipher = AES.new(doc_key, AES.MODE_CBC, iv)
        content = unpad(cipher.decrypt(ct), AES.block_size).decode()

        self.log_access(doc_id, 'VIEWED')
        return content

    def log_access(self, doc_id, action):
        if doc_id in self.documents:
            log_entry = {
                'user': self.current_user,
                'action': action,
                'timestamp': datetime.now().isoformat()
            }
            self.documents[doc_id]['access_log'].append(log_entry)

    def list_documents(self, filter_dept=None):
        """List documents accessible to current user"""
        user_dept = self.users[self.current_user]['dept']
        user_role = self.users[self.current_user]['role']

        accessible = []

        for doc_id, doc in self.documents.items():
            # Directors can see all
            if user_role == 'director':
                accessible.append(doc_id)
            # Managers can see their department's documents
            elif user_role == 'manager' and doc['dept'] == user_dept:
                accessible.append(doc_id)
            # Employees can see documents they created or have access to
            elif self.current_user in doc['encrypted_keys']:
                accessible.append(doc_id)

        return accessible


def main():
    dms = DocumentManagementSystem()

    print("📄 CORPORATE DOCUMENT MANAGEMENT SYSTEM")
    print("=" * 60)
    print("Users: employee1, employee2, manager1, manager2, director")
    print("Password for all: emp123/emp456/mgr123/mgr456/dir123")

    # Login
    while True:
        print("\n🔐 Login")
        user = input("Username: ")
        pwd = input("Password: ")

        if dms.login(user, pwd):
            print(f"✅ Welcome, {user}!")
            break
        else:
            print("❌ Invalid credentials")

    # Main menu
    while True:
        user_info = dms.users[dms.current_user]
        print(f"\n👤 {dms.current_user} ({user_info['role']}, {user_info['dept']})")
        print("\n1. Create Document")
        print("2. Sign Document")
        print("3. View Document")
        print("4. Verify Signature")
        print("5. List My Documents")
        print("6. Document Details")
        print("7. Exit")

        choice = input("\nSelect option: ")

        if choice == '1':
            print("\n📝 CREATE DOCUMENT")
            content = input("Document content: ")

            print("\nSelect recipients (comma-separated):")
            print("Available: " + ", ".join(dms.users.keys()))
            recipients_input = input("Recipients: ")
            recipients = [r.strip() for r in recipients_input.split(',') if r.strip() in dms.users]

            if recipients:
                doc_id = dms.encrypt_document(content, recipients)
                print(f"✅ Document created: {doc_id}")
                print(f"Encrypted and accessible to: {', '.join(recipients)}")
            else:
                print("❌ No valid recipients selected")

        elif choice == '2':
            print("\n✍️ SIGN DOCUMENT")
            doc_id = input("Document ID: ")
            result = dms.sign_document(doc_id)
            print(result)

        elif choice == '3':
            print("\n👁 VIEW DOCUMENT")
            doc_id = input("Document ID: ")
            content = dms.decrypt_document(doc_id)

            if content.startswith("Access denied"):
                print("❌ " + content)
            elif content.startswith("Document not found"):
                print("❌ " + content)
            else:
                print(f"\n📄 DOCUMENT {doc_id}:")
                print("-" * 40)
                print(content)
                print("-" * 40)

        elif choice == '4':
            print("\n🔍 VERIFY SIGNATURE")
            doc_id = input("Document ID: ")
            signer = input("Signer username: ")
            result = dms.verify_signature(doc_id, signer)
            print(result)

        elif choice == '5':
            print("\n📋 MY DOCUMENTS")
            docs = dms.list_documents()
            if docs:
                for doc_id in docs:
                    doc = dms.documents[doc_id]
                    print(f"\n{doc_id}: {doc['title']}")
                    print(f"  Author: {doc['author']}, Dept: {doc['dept']}")
                    print(f"  Created: {doc['timestamp'][:19]}")
                    print(f"  Signatures: {len(doc['signatures'])}")
            else:
                print("No documents found")

        elif choice == '6':
            print("\n🔎 DOCUMENT DETAILS")
            doc_id = input("Document ID: ")

            if doc_id in dms.documents:
                doc = dms.documents[doc_id]
                print(f"\nID: {doc_id}")
                print(f"Title: {doc['title']}")
                print(f"Author: {doc['author']}")
                print(f"Department: {doc['dept']}")
                print(f"Created: {doc['timestamp']}")
                print(f"\nAccessible to: {', '.join(doc['encrypted_keys'].keys())}")
                print(f"\nSignatures:")
                for signer, sig_info in doc['signatures'].items():
                    print(f"  {signer} ({sig_info['role']}) at {sig_info['timestamp'][:19]}")
                print(f"\nAccess Log (last 5):")
                for log in doc['access_log'][-5:]:
                    print(f"  {log['timestamp'][:19]} - {log['user']}: {log['action']}")
            else:
                print("❌ Document not found")

        elif choice == '7':
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    main()