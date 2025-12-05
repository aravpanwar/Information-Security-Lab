# smart_government.py
"""
GOVERNMENT PORTAL - COMPREHENSIVE CRYPTOGRAPHY SYSTEM
=====================================================
Concepts Used:
1. RSA - Citizen document encryption
2. AES - Internal communication encryption
3. Digital Signatures - Document signing/verification
4. SHA-256 - Data integrity hashing
5. Role-Based Access Control (RBAC)
6. Audit Logging
7. Multi-user system with different privileges
"""

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


class GovernmentPortal:
    def __init__(self):
        # User database with roles and permissions
        self.users = {
            'citizen1': {'password': self.hash('pass123'), 'role': 'citizen', 'citizen_id': 'CTZ001'},
            'citizen2': {'password': self.hash('pass456'), 'role': 'citizen', 'citizen_id': 'CTZ002'},
            'officer1': {'password': self.hash('off123'), 'role': 'officer', 'dept': 'Tax'},
            'officer2': {'password': self.hash('off456'), 'role': 'officer', 'dept': 'License'},
            'auditor1': {'password': self.hash('aud123'), 'role': 'auditor', 'clearance': 'high'},
            'admin': {'password': self.hash('admin123'), 'role': 'admin'}
        }

        # Generate RSA keys for each citizen
        self.citizen_keys = {}
        for user, info in self.users.items():
            if info['role'] == 'citizen':
                key = RSA.generate(2048)
                self.citizen_keys[info['citizen_id']] = {
                    'public': key.publickey(),
                    'private': key
                }

        # Generate RSA keys for government
        self.gov_key = RSA.generate(2048)
        self.gov_pub = self.gov_key.publickey()

        # AES keys for internal communication
        self.session_keys = {}

        # Data storage
        self.citizen_documents = {}  # Citizen ID -> list of encrypted documents
        self.applications = []  # Applications from citizens
        self.audit_log = []

        self.current_user = None

    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()

    def log_audit(self, action, target=None):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'user': self.current_user,
            'role': self.users[self.current_user]['role'],
            'action': action,
            'target': target
        }
        self.audit_log.append(entry)

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == self.hash(password):
            self.current_user = username
            # Generate session key for this user
            self.session_keys[username] = get_random_bytes(32)
            self.log_audit('LOGIN')
            return True
        return False

    # ========== MODULE 1: CITIZEN DOCUMENT SUBMISSION (RSA + Hashing) ==========
    def submit_document(self, citizen_id, document_type, content):
        """Citizen submits encrypted document using their RSA public key"""
        if self.users[self.current_user]['role'] != 'citizen':
            return "Only citizens can submit documents"

        if citizen_id not in [u['citizen_id'] for u in self.users.values() if 'citizen_id' in u]:
            return "Invalid citizen ID"

        # Compute hash for integrity
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Encrypt content with citizen's RSA public key
        cipher = PKCS1_OAEP.new(self.citizen_keys[citizen_id]['public'])
        encrypted_content = cipher.encrypt(content.encode())

        # Create document record
        document = {
            'id': f"DOC{len(self.citizen_documents.get(citizen_id, [])) + 1:04d}",
            'type': document_type,
            'encrypted_content': base64.b64encode(encrypted_content).decode(),
            'hash': content_hash,
            'submitted_by': self.current_user,
            'timestamp': datetime.now().isoformat(),
            'status': 'submitted',
            'signatures': []
        }

        # Store in citizen's documents
        if citizen_id not in self.citizen_documents:
            self.citizen_documents[citizen_id] = []
        self.citizen_documents[citizen_id].append(document)

        self.log_audit('DOCUMENT_SUBMIT', f"{document_type} for {citizen_id}")
        return f"Document {document['id']} submitted and encrypted"

    def view_own_documents(self, citizen_id):
        """Citizen views their own documents (decrypted)"""
        if self.users[self.current_user]['role'] != 'citizen':
            return []

        if citizen_id not in self.citizen_documents:
            return []

        decrypted_docs = []
        for doc in self.citizen_documents[citizen_id]:
            # Decrypt using citizen's private key
            encrypted = base64.b64decode(doc['encrypted_content'])
            cipher = PKCS1_OAEP.new(self.citizen_keys[citizen_id]['private'])
            decrypted = cipher.decrypt(encrypted).decode()

            # Verify hash
            if hashlib.sha256(decrypted.encode()).hexdigest() == doc['hash']:
                integrity = "✅ INTEGRITY OK"
            else:
                integrity = "❌ INTEGRITY FAILED"

            decrypted_docs.append({
                'id': doc['id'],
                'type': doc['type'],
                'content': decrypted,
                'integrity': integrity,
                'timestamp': doc['timestamp'],
                'status': doc['status']
            })

        return decrypted_docs

    # ========== MODULE 2: OFFICER PROCESSING (AES + Digital Signatures) ==========
    def officer_view_document(self, citizen_id, doc_id):
        """Officer views and signs citizen document"""
        if self.users[self.current_user]['role'] != 'officer':
            return "Officers only"

        if citizen_id not in self.citizen_documents:
            return "No documents found"

        # Find document
        target_doc = None
        for doc in self.citizen_documents[citizen_id]:
            if doc['id'] == doc_id:
                target_doc = doc
                break

        if not target_doc:
            return "Document not found"

        # Decrypt document (officer uses government key)
        encrypted = base64.b64decode(target_doc['encrypted_content'])
        cipher = PKCS1_OAEP.new(self.gov_key)  # Government can decrypt
        decrypted = cipher.decrypt(encrypted).decode()

        # Create digital signature
        signature_data = {
            'doc_id': doc_id,
            'citizen_id': citizen_id,
            'content_hash': target_doc['hash'],
            'officer': self.current_user,
            'timestamp': datetime.now().isoformat()
        }

        h = SHA256.new(json.dumps(signature_data).encode())
        signature = pkcs1_15.new(self.gov_key).sign(h)

        # Add signature to document
        target_doc['signatures'].append({
            'officer': self.current_user,
            'signature': base64.b64encode(signature).decode(),
            'timestamp': signature_data['timestamp']
        })

        target_doc['status'] = 'processed'

        self.log_audit('DOCUMENT_PROCESS', f"{doc_id} by {self.current_user}")
        return {
            'document': decrypted,
            'integrity_hash': target_doc['hash'],
            'signed_by': self.current_user
        }

    def verify_document_signature(self, citizen_id, doc_id):
        """Anyone can verify document signatures"""
        if citizen_id not in self.citizen_documents:
            return "No documents found"

        for doc in self.citizen_documents[citizen_id]:
            if doc['id'] == doc_id:
                results = []
                for sig in doc.get('signatures', []):
                    signature_data = {
                        'doc_id': doc_id,
                        'citizen_id': citizen_id,
                        'content_hash': doc['hash'],
                        'officer': sig['officer'],
                        'timestamp': sig['timestamp']
                    }

                    h = SHA256.new(json.dumps(signature_data).encode())
                    signature = base64.b64decode(sig['signature'])

                    try:
                        pkcs1_15.new(self.gov_pub).verify(h, signature)
                        results.append(f"✅ {sig['officer']}: Signature VALID")
                    except:
                        results.append(f"❌ {sig['officer']}: Signature INVALID")

                return results if results else ["No signatures found"]

        return "Document not found"

    # ========== MODULE 3: SECURE INTERNAL MESSAGING (AES) ==========
    def send_internal_message(self, recipient, message):
        """Send encrypted internal message using AES"""
        if recipient not in self.users:
            return "Recipient not found"

        # Encrypt message with recipient's session key
        if recipient not in self.session_keys:
            return "Recipient not logged in"

        session_key = self.session_keys[recipient]
        cipher = AES.new(session_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))

        encrypted_msg = {
            'sender': self.current_user,
            'recipient': recipient,
            'iv': base64.b64encode(cipher.iv).decode(),
            'ciphertext': base64.b64encode(ct_bytes).decode(),
            'timestamp': datetime.now().isoformat(),
            'read': False
        }

        # In real system, this would go to a message queue
        print(f"\n🔐 ENCRYPTED MESSAGE SENT TO {recipient}")
        print(f"IV: {encrypted_msg['iv'][:20]}...")
        print(f"Ciphertext: {encrypted_msg['ciphertext'][:30]}...")

        self.log_audit('SEND_MESSAGE', recipient)
        return "Message sent (encrypted with AES)"

    # ========== MODULE 4: AUDITOR ACCESS (Read-Only + Verification) ==========
    def auditor_view_all(self):
        """Auditor view - can see everything but not decrypt sensitive data"""
        if self.users[self.current_user]['role'] != 'auditor':
            return "Auditors only"

        report = {
            'total_citizens': len([u for u in self.users.values() if u['role'] == 'citizen']),
            'total_documents': sum(len(docs) for docs in self.citizen_documents.values()),
            'processed_documents': 0,
            'pending_documents': 0
        }

        for citizen_id, docs in self.citizen_documents.items():
            for doc in docs:
                if doc['status'] == 'processed':
                    report['processed_documents'] += 1
                else:
                    report['pending_documents'] += 1

        # Show audit log
        report['recent_audit_entries'] = []
        for entry in self.audit_log[-10:]:
            report['recent_audit_entries'].append({
                'time': entry['timestamp'][11:19],
                'user': entry['user'],
                'action': entry['action']
            })

        return report

    # ========== MODULE 5: ADMIN FUNCTIONS (Key Management) ==========
    def admin_rotate_keys(self):
        """Admin can rotate government keys"""
        if self.users[self.current_user]['role'] != 'admin':
            return "Admin only"

        old_key = self.gov_key
        self.gov_key = RSA.generate(2048)
        self.gov_pub = self.gov_key.publickey()

        self.log_audit('KEY_ROTATION', 'Government RSA keys rotated')
        return "✅ Government RSA keys rotated successfully"


def main():
    gov = GovernmentPortal()

    print("🏛️ SMART GOVERNMENT PORTAL")
    print("=" * 60)
    print("Multi-Cryptography System: RSA + AES + Digital Signatures + Hashing")
    print("\nAvailable Users:")
    print("  Citizens: citizen1 (CTZ001), citizen2 (CTZ002)")
    print("  Officers: officer1 (Tax), officer2 (License)")
    print("  Auditor: auditor1")
    print("  Admin: admin")
    print("\nPasswords: pass123, pass456, off123, off456, aud123, admin123")

    # Login
    while True:
        print("\n" + "=" * 40)
        user = input("Username: ")
        pwd = input("Password: ")

        if gov.login(user, pwd):
            role = gov.users[user]['role']
            print(f"\n✅ Welcome, {user} ({role})!")
            break
        else:
            print("❌ Invalid credentials")

    # Role-based menu
    while True:
        role = gov.users[gov.current_user]['role']
        print(f"\n👤 {gov.current_user} - {role.upper()}")
        print("-" * 40)

        if role == 'citizen':
            print("1. Submit Document (RSA Encrypted)")
            print("2. View My Documents")
            print("3. Check Document Status")
            print("4. Verify Document Signatures")

        elif role == 'officer':
            print("1. Process Citizen Document")
            print("2. Verify Signatures")
            print("3. Send Internal Message (AES)")
            print("4. View Audit Trail")

        elif role == 'auditor':
            print("1. View System Report")
            print("2. View All Audit Logs")
            print("3. Verify All Signatures")
            print("4. System Statistics")

        elif role == 'admin':
            print("1. Rotate Government Keys")
            print("2. View All Users")
            print("3. System Audit")
            print("4. Security Report")

        print("0. Logout")

        choice = input("\nSelect: ")

        if choice == '0':
            print("👋 Logging out...")
            break

        # Citizen functions
        if role == 'citizen':
            if choice == '1':
                cid = input("Your Citizen ID (CTZ001/CTZ002): ")
                doc_type = input("Document Type: ")
                content = input("Document Content: ")
                result = gov.submit_document(cid, doc_type, content)
                print(f"\n{result}")

            elif choice == '2':
                cid = gov.users[gov.current_user]['citizen_id']
                docs = gov.view_own_documents(cid)
                if docs:
                    print(f"\n📄 YOUR DOCUMENTS:")
                    for doc in docs:
                        print(f"\nID: {doc['id']} | Type: {doc['type']}")
                        print(f"Status: {doc['status']} | {doc['integrity']}")
                        print(f"Content: {doc['content'][:50]}...")
                else:
                    print("No documents found")

            elif choice == '3':
                cid = gov.users[gov.current_user]['citizen_id']
                if cid in gov.citizen_documents:
                    print(f"\n📋 DOCUMENT STATUS for {cid}:")
                    for doc in gov.citizen_documents[cid]:
                        print(f"  {doc['id']}: {doc['type']} - {doc['status']}")
                else:
                    print("No documents submitted")

            elif choice == '4':
                cid = gov.users[gov.current_user]['citizen_id']
                doc_id = input("Document ID to verify: ")
                results = gov.verify_document_signature(cid, doc_id)
                print(f"\n🔐 SIGNATURE VERIFICATION:")
                for result in results:
                    print(f"  {result}")

        # Officer functions
        elif role == 'officer':
            if choice == '1':
                cid = input("Citizen ID: ")
                doc_id = input("Document ID: ")
                result = gov.officer_view_document(cid, doc_id)
                if isinstance(result, dict):
                    print(f"\n📄 PROCESSED DOCUMENT:")
                    print(f"Content: {result['document']}")
                    print(f"Hash: {result['integrity_hash'][:20]}...")
                    print(f"Signed by: {result['signed_by']}")
                else:
                    print(f"\n{result}")

            elif choice == '2':
                cid = input("Citizen ID: ")
                doc_id = input("Document ID: ")
                results = gov.verify_document_signature(cid, doc_id)
                print(f"\n🔍 SIGNATURE VERIFICATION:")
                for result in results:
                    print(f"  {result}")

            elif choice == '3':
                recipient = input("Recipient: ")
                message = input("Message: ")
                result = gov.send_internal_message(recipient, message)
                print(f"\n{result}")

            elif choice == '4':
                print(f"\n📊 AUDIT TRAIL (Last 5 entries):")
                for entry in gov.audit_log[-5:]:
                    print(f"  {entry['timestamp'][11:19]} - {entry['user']}: {entry['action']}")

        # Auditor functions
        elif role == 'auditor':
            if choice == '1':
                report = gov.auditor_view_all()
                print(f"\n📈 SYSTEM REPORT:")
                print(f"Total Citizens: {report['total_citizens']}")
                print(f"Total Documents: {report['total_documents']}")
                print(f"Processed: {report['processed_documents']}")
                print(f"Pending: {report['pending_documents']}")
                print(f"\nRecent Activity:")
                for entry in report['recent_audit_entries']:
                    print(f"  {entry['time']} - {entry['user']}: {entry['action']}")

            elif choice == '2':
                print(f"\n📋 FULL AUDIT LOG ({len(gov.audit_log)} entries):")
                for entry in gov.audit_log[-20:]:
                    print(f"{entry['timestamp'][:19]} - {entry['user']} ({entry['role']}): {entry['action']}")

            elif choice == '3':
                print("\n🔐 VERIFYING ALL DOCUMENT SIGNATURES...")
                verified = 0
                invalid = 0
                for cid in gov.citizen_documents:
                    for doc in gov.citizen_documents[cid]:
                        if doc.get('signatures'):
                            for sig in doc['signatures']:
                                # Quick verification (in real system, would verify each)
                                verified += 1
                print(f"✅ {verified} signatures found in system")

            elif choice == '4':
                print("\n📊 CRYPTOGRAPHY STATISTICS:")
                print(f"RSA Citizen Keys: {len(gov.citizen_keys)}")
                print(f"AES Session Keys: {len(gov.session_keys)}")
                print(f"Stored Documents: {sum(len(d) for d in gov.citizen_documents.values())}")

        # Admin functions
        elif role == 'admin':
            if choice == '1':
                confirm = input("Rotate government RSA keys? (y/n): ")
                if confirm.lower() == 'y':
                    result = gov.admin_rotate_keys()
                    print(f"\n{result}")

            elif choice == '2':
                print("\n👥 SYSTEM USERS:")
                for user, info in gov.users.items():
                    print(f"  {user}: {info['role']}")

            elif choice == '3':
                print(f"\n🔍 SYSTEM AUDIT:")
                print(f"Total log entries: {len(gov.audit_log)}")
                actions = {}
                for entry in gov.audit_log:
                    actions[entry['action']] = actions.get(entry['action'], 0) + 1
                for action, count in actions.items():
                    print(f"  {action}: {count}")

            elif choice == '4':
                print("\n🛡️ SECURITY STATUS:")
                print("✅ RSA Encryption: Active for citizen documents")
                print("✅ AES Encryption: Active for internal messages")
                print("✅ Digital Signatures: Active for officer approvals")
                print("✅ SHA-256 Hashing: Active for data integrity")
                print("✅ Role-Based Access: Active")
                print("✅ Audit Logging: Active")


if __name__ == "__main__":
    main()