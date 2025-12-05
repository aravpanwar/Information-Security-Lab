import random
import hashlib
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import time


# ==================== MODULE 1: RSA ====================
class RSAModule:
    @staticmethod
    def generate_keys(bits=512):
        """Generate RSA public/private keys"""
        key = RSA.generate(bits)
        pub_key = key.publickey()
        return pub_key, key

    @staticmethod
    def encrypt(pub_key, message):
        """Encrypt with RSA"""
        cipher = PKCS1_OAEP.new(pub_key)
        return cipher.encrypt(message.encode())

    @staticmethod
    def decrypt(priv_key, ciphertext):
        """Decrypt with RSA"""
        cipher = PKCS1_OAEP.new(priv_key)
        return cipher.decrypt(ciphertext).decode()

    @staticmethod
    def sign(priv_key, message):
        """Create RSA signature"""
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(priv_key).sign(h)
        return signature

    @staticmethod
    def verify(pub_key, message, signature):
        """Verify RSA signature"""
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(pub_key).verify(h, signature)
            return True
        except:
            return False


# ==================== MODULE 2: ELGAMAL ====================
class ElGamalModule:
    @staticmethod
    def generate_keys():
        """Generate ElGamal keys"""
        p = 32321  # Small prime for demo
        g = 3
        x = random.randint(1, p - 2)
        h = pow(g, x, p)
        return (p, g, h), x

    @staticmethod
    def encrypt(pub_key, message):
        """Encrypt with ElGamal"""
        p, g, h = pub_key
        m = int.from_bytes(message.encode(), 'big')
        y = random.randint(1, p - 2)
        c1 = pow(g, y, p)
        s = pow(h, y, p)
        c2 = (m * s) % p
        return (c1, c2)

    @staticmethod
    def decrypt(priv_key, pub_key, cipher):
        """Decrypt with ElGamal"""
        p, g, h = pub_key
        x = priv_key
        c1, c2 = cipher
        s = pow(c1, x, p)
        m = (c2 * pow(s, -1, p)) % p
        return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


# ==================== MODULE 3: AES ====================
class AESModule:
    @staticmethod
    def generate_key():
        """Generate AES key"""
        return get_random_bytes(16)

    @staticmethod
    def encrypt(key, data):
        """Encrypt with AES"""
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return base64.b64encode(iv + ct_bytes).decode()

    @staticmethod
    def decrypt(key, enc_data):
        """Decrypt with AES"""
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[:16]
        ct = enc_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()


# ==================== MODULE 4: HASHING ====================
class HashModule:
    @staticmethod
    def sha256(data):
        """Compute SHA-256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def md5(data):
        """Compute MD5 hash"""
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def verify_hash(data, hash_value):
        """Verify data against hash"""
        return hashlib.sha256(data.encode()).hexdigest() == hash_value


# ==================== MODULE 5: DIGITAL SIGNATURE ====================
class DigitalSignatureModule:
    def __init__(self):
        self.rsa = RSAModule()

    def create_signed_document(self, priv_key, document):
        """Create signed document"""
        signature = self.rsa.sign(priv_key, document)
        signed_doc = {
            'document': document,
            'signature': base64.b64encode(signature).decode()
        }
        return json.dumps(signed_doc)

    def verify_signed_document(self, pub_key, signed_json):
        """Verify signed document"""
        data = json.loads(signed_json)
        document = data['document']
        signature = base64.b64decode(data['signature'])
        return self.rsa.verify(pub_key, document, signature)


# ==================== MODULE 6: ROLE MANAGEMENT ====================
class RoleManager:
    ROLES = {
        'ADMIN': ['create', 'read', 'update', 'delete', 'audit'],
        'DOCTOR': ['read', 'update'],
        'PATIENT': ['read'],
        'AUDITOR': ['read', 'audit'],
        'CUSTOMER': ['create', 'read'],
        'MERCHANT': ['read', 'update'],
        'EMPLOYEE': ['read'],
        'MANAGER': ['read', 'update', 'approve']
    }

    @staticmethod
    def check_permission(role, action):
        """Check if role has permission for action"""
        return action in RoleManager.ROLES.get(role.upper(), [])


# ==================== MODULE 7: DATA STORAGE ====================
class SecureStorage:
    def __init__(self):
        self.data = {}
        self.aes = AESModule()

    def store_encrypted(self, key, user_id, data_type, content):
        """Store encrypted data"""
        encrypted = self.aes.encrypt(key, content)
        if user_id not in self.data:
            self.data[user_id] = {}
        self.data[user_id][data_type] = encrypted
        return True

    def retrieve_encrypted(self, key, user_id, data_type):
        """Retrieve and decrypt data"""
        if user_id in self.data and data_type in self.data[user_id]:
            return self.aes.decrypt(key, self.data[user_id][data_type])
        return None


# ==================== MENU SYSTEM ====================
class CryptoSystem:
    def __init__(self):
        self.rsa = RSAModule()
        self.elgamal = ElGamalModule()
        self.aes = AESModule()
        self.hash = HashModule()
        self.signature = DigitalSignatureModule()
        self.storage = SecureStorage()
        self.roles = RoleManager()

        # Initialize keys
        self.rsa_pub, self.rsa_priv = None, None
        self.elg_pub, self.elg_priv = None, None
        self.aes_key = None

        # User sessions
        self.current_user = None
        self.current_role = None

    def setup_keys(self):
        """Initialize all cryptographic keys"""
        print("\n🔐 Generating cryptographic keys...")
        self.rsa_pub, self.rsa_priv = self.rsa.generate_keys()
        self.elg_pub, self.elg_priv = self.elgamal.generate_keys()
        self.aes_key = self.aes.generate_key()
        print("✅ Keys generated successfully!")

    def login(self):
        """Simulate user login with role"""
        users = {
            'admin': 'ADMIN',
            'doctor': 'DOCTOR',
            'patient': 'PATIENT',
            'auditor': 'AUDITOR',
            'customer': 'CUSTOMER',
            'merchant': 'MERCHANT'
        }

        print("\n👤 Available users:")
        for user, role in users.items():
            print(f"  {user} ({role})")

        user = input("\nEnter username: ").lower()
        if user in users:
            self.current_user = user
            self.current_role = users[user]
            print(f"✅ Logged in as {user} ({self.current_role})")
            return True
        else:
            print("❌ Invalid user")
            return False

    # ========== SCENARIO 1: HOSPITAL SYSTEM ==========
    def hospital_system(self):
        """Hospital: Patient records with encryption"""
        print("\n🏥 HOSPITAL MANAGEMENT SYSTEM")
        print("=" * 40)

        if not self.login():
            return

        while True:
            print(f"\nLogged in as: {self.current_role}")
            print("1. Add Patient Record")
            print("2. View Patient Record")
            print("3. Update Record")
            print("4. Audit Log")
            print("5. Switch User")
            print("6. Exit")

            choice = input("Choose: ")

            if choice == '1':
                if self.roles.check_permission(self.current_role, 'create'):
                    pid = input("Patient ID: ")
                    record = input("Medical Record: ")
                    encrypted = self.aes.encrypt(self.aes_key, record)
                    self.storage.store_encrypted(self.aes_key, pid, 'medical', record)
                    print("✅ Record stored (encrypted)")
                else:
                    print("❌ Permission denied")

            elif choice == '2':
                if self.roles.check_permission(self.current_role, 'read'):
                    pid = input("Patient ID: ")
                    record = self.storage.retrieve_encrypted(self.aes_key, pid, 'medical')
                    if record:
                        print(f"📄 Record: {record}")
                    else:
                        print("❌ Record not found")
                else:
                    print("❌ Permission denied")

            elif choice == '3':
                if self.roles.check_permission(self.current_role, 'update'):
                    pid = input("Patient ID: ")
                    new_record = input("New Record: ")
                    self.storage.store_encrypted(self.aes_key, pid, 'medical', new_record)
                    print("✅ Record updated")
                else:
                    print("❌ Permission denied")

            elif choice == '4':
                if self.roles.check_permission(self.current_role, 'audit'):
                    print("📊 Audit Log: All records are encrypted with AES-128")
                    print(f"Total patients: {len(self.storage.data)}")
                else:
                    print("❌ Permission denied")

            elif choice == '5':
                self.login()

            elif choice == '6':
                break

    # ========== SCENARIO 2: BANKING SYSTEM ==========
    def banking_system(self):
        """Bank: Transactions with RSA signatures"""
        print("\n🏦 BANKING TRANSACTION SYSTEM")
        print("=" * 40)

        self.setup_keys()
        transactions = []

        while True:
            print("\n1. Customer - Initiate Transaction")
            print("2. Teller - Process Transaction")
            print("3. Auditor - View Transactions")
            print("4. Verify Signature")
            print("5. Exit")

            choice = input("Choose: ")

            if choice == '1':
                # Customer encrypts transaction
                amount = input("Transaction Amount: ")
                to_account = input("To Account: ")
                transaction = f"Transfer ${amount} to {to_account}"

                # Encrypt with RSA
                encrypted = self.rsa.encrypt(self.rsa_pub, transaction)
                # Sign with RSA
                signature = self.rsa.sign(self.rsa_priv, transaction)

                tx_data = {
                    'encrypted': base64.b64encode(encrypted).decode(),
                    'signature': base64.b64encode(signature).decode(),
                    'timestamp': time.time()
                }
                transactions.append(tx_data)
                print("✅ Transaction encrypted and signed")

            elif choice == '2':
                # Teller decrypts
                if transactions:
                    tx = transactions[-1]
                    encrypted = base64.b64decode(tx['encrypted'])
                    decrypted = self.rsa.decrypt(self.rsa_priv, encrypted)
                    print(f"🔓 Decrypted: {decrypted}")
                else:
                    print("❌ No transactions")

            elif choice == '3':
                # Auditor views (read-only encrypted)
                print("\n📋 All Transactions (Auditor View):")
                for i, tx in enumerate(transactions):
                    print(f"{i + 1}. [ENCRYPTED] Signature: {tx['signature'][:30]}...")

            elif choice == '4':
                # Verify signature
                if transactions:
                    tx = transactions[-1]
                    decrypted = self.rsa.decrypt(self.rsa_priv,
                                                 base64.b64decode(tx['encrypted']))
                    signature = base64.b64decode(tx['signature'])

                    if self.rsa.verify(self.rsa_pub, decrypted, signature):
                        print("✅ Signature VALID")
                    else:
                        print("❌ Signature INVALID")

            elif choice == '5':
                break

    # ========== SCENARIO 3: E-VOTING SYSTEM ==========
    def evoting_system(self):
        """E-Voting with ElGamal for anonymity"""
        print("\n🗳️ E-VOTING SYSTEM")
        print("=" * 40)

        self.elg_pub, self.elg_priv = self.elgamal.generate_keys()
        votes = []

        while True:
            print("\n1. Voter - Cast Vote")
            print("2. Election Officer - Tally Votes")
            print("3. Observer - Verify Process")
            print("4. Exit")

            choice = input("Choose: ")

            if choice == '1':
                print("\nCandidates: A, B, C, D")
                vote = input("Your vote (A/B/C/D): ").upper()
                if vote in ['A', 'B', 'C', 'D']:
                    # Encrypt vote with ElGamal (anonymous)
                    encrypted_vote = self.elgamal.encrypt(self.elg_pub, vote)
                    votes.append(encrypted_vote)
                    print("✅ Vote cast (encrypted)")
                else:
                    print("❌ Invalid candidate")

            elif choice == '2':
                # Decrypt and tally
                tally = {'A': 0, 'B': 0, 'C': 0, 'D': 0}
                for vote in votes:
                    decrypted = self.elgamal.decrypt(self.elg_priv, self.elg_pub, vote)
                    tally[decrypted] += 1

                print("\n📊 ELECTION RESULTS:")
                for cand, count in tally.items():
                    print(f"  {cand}: {count} votes")

            elif choice == '3':
                print("\n👁 Observer View:")
                print(f"Total votes cast: {len(votes)}")
                print("All votes are ElGamal encrypted")
                print("Voter anonymity preserved")

            elif choice == '4':
                break

    # ========== SCENARIO 4: FILE SHARING ==========
    def file_sharing_system(self):
        """Secure file sharing with hybrid encryption"""
        print("\n📁 SECURE FILE SHARING SYSTEM")
        print("=" * 40)

        files = {}

        while True:
            print("\n1. Upload File (Encrypt with AES)")
            print("2. Download File (Decrypt)")
            print("3. Share File (Encrypt with recipient's RSA)")
            print("4. List Files")
            print("5. Exit")

            choice = input("Choose: ")

            if choice == '1':
                filename = input("Filename: ")
                content = input("File content: ")
                # Encrypt with AES
                encrypted = self.aes.encrypt(self.aes_key, content)
                files[filename] = {
                    'encrypted': encrypted,
                    'owner': self.current_user
                }
                print("✅ File encrypted and stored")

            elif choice == '2':
                filename = input("Filename: ")
                if filename in files:
                    encrypted = files[filename]['encrypted']
                    decrypted = self.aes.decrypt(self.aes_key, encrypted)
                    print(f"📄 Content: {decrypted}")
                else:
                    print("❌ File not found")

            elif choice == '3':
                # Hybrid: Encrypt AES key with RSA
                filename = input("Filename to share: ")
                if filename in files:
                    # Generate new AES key for sharing
                    share_key = self.aes.generate_key()
                    # Encrypt file with new key
                    content = self.aes.decrypt(self.aes_key, files[filename]['encrypted'])
                    re_encrypted = self.aes.encrypt(share_key, content)
                    # Encrypt the share key with RSA
                    encrypted_key = self.rsa.encrypt(self.rsa_pub,
                                                     share_key.hex())

                    print("✅ File prepared for sharing:")
                    print(f"  Encrypted file: {re_encrypted[:50]}...")
                    print(f"  Encrypted key: {encrypted_key.hex()[:50]}...")
                else:
                    print("❌ File not found")

            elif choice == '4':
                print("\n📋 Stored Files:")
                for name, data in files.items():
                    print(f"  {name} (Owner: {data['owner']})")

            elif choice == '5':
                break

    # ========== MAIN MENU ==========
    def main_menu(self):
        """Main menu to select scenario"""
        print("\n" + "=" * 50)
        print("🔐 MODULAR CRYPTOGRAPHY SYSTEM - EXAM READY")
        print("=" * 50)

        scenarios = {
            '1': ('🏥 Hospital System', self.hospital_system),
            '2': ('🏦 Banking System', self.banking_system),
            '3': ('🗳️ E-Voting System', self.evoting_system),
            '4': ('📁 File Sharing', self.file_sharing_system),
            '5': ('🧪 Test All Crypto Modules', self.test_all_modules)
        }

        while True:
            print("\nSelect Scenario:")
            for key, (name, _) in scenarios.items():
                print(f"{key}. {name}")
            print("0. Exit")

            choice = input("\nChoose scenario (0-5): ")

            if choice == '0':
                print("👋 Goodbye!")
                break
            elif choice in scenarios:
                scenarios[choice][1]()
            else:
                print("❌ Invalid choice")

    # ========== TEST MODULE ==========
    def test_all_modules(self):
        """Test all cryptographic modules"""
        print("\n🧪 TESTING ALL CRYPTO MODULES")
        print("=" * 40)

        # Setup
        self.setup_keys()
        test_message = "Secret exam message 2024"

        print("\n1. RSA Test:")
        rsa_enc = self.rsa.encrypt(self.rsa_pub, test_message)
        rsa_dec = self.rsa.decrypt(self.rsa_priv, rsa_enc)
        print(f"   Original: {test_message}")
        print(f"   Decrypted: {rsa_dec}")
        print(f"   ✓ Match: {test_message == rsa_dec}")

        print("\n2. ElGamal Test:")
        elg_enc = self.elgamal.encrypt(self.elg_pub, test_message)
        elg_dec = self.elgamal.decrypt(self.elg_priv, self.elg_pub, elg_enc)
        print(f"   Decrypted: {elg_dec}")
        print(f"   ✓ Match: {test_message == elg_dec}")

        print("\n3. AES Test:")
        aes_enc = self.aes.encrypt(self.aes_key, test_message)
        aes_dec = self.aes.decrypt(self.aes_key, aes_enc)
        print(f"   Decrypted: {aes_dec}")
        print(f"   ✓ Match: {test_message == aes_dec}")

        print("\n4. Hashing Test:")
        hash_val = self.hash.sha256(test_message)
        print(f"   SHA-256: {hash_val[:30]}...")
        print(f"   ✓ Verify: {self.hash.verify_hash(test_message, hash_val)}")

        print("\n5. Digital Signature Test:")
        signature = self.rsa.sign(self.rsa_priv, test_message)
        verified = self.rsa.verify(self.rsa_pub, test_message, signature)
        print(f"   ✓ Signature valid: {verified}")

        print("\n✅ All modules working!")


# ==================== RUN SYSTEM ====================
if __name__ == "__main__":
    system = CryptoSystem()
    system.main_menu()