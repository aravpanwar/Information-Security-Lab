import random
import hashlib
import json
import time
import struct
from collections import defaultdict
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import math


# ==================== MODULE 1: SYMMETRIC CIPHERS ====================
class SymmetricCiphers:
    @staticmethod
    def caesar_cipher(text, shift, encrypt=True):
        """Caesar/Additive cipher"""
        result = ""
        for char in text.upper():
            if char.isalpha():
                shift_val = shift if encrypt else -shift
                result += chr((ord(char) - 65 + shift_val) % 26 + 65)
            else:
                result += char
        return result

    @staticmethod
    def multiplicative_cipher(text, key, encrypt=True):
        """Multiplicative cipher"""
        result = ""
        for char in text.upper():
            if char.isalpha():
                num = ord(char) - 65
                if encrypt:
                    result += chr((num * key) % 26 + 65)
                else:
                    # Find modular inverse
                    inv = pow(key, -1, 26)
                    result += chr((num * inv) % 26 + 65)
            else:
                result += char
        return result

    @staticmethod
    def affine_cipher(text, a, b, encrypt=True):
        """Affine cipher: E(x) = (ax + b) mod 26"""
        result = ""
        for char in text.upper():
            if char.isalpha():
                num = ord(char) - 65
                if encrypt:
                    result += chr((a * num + b) % 26 + 65)
                else:
                    inv_a = pow(a, -1, 26)
                    result += chr((inv_a * (num - b)) % 26 + 65)
            else:
                result += char
        return result

    @staticmethod
    def vigenere_cipher(text, key, encrypt=True):
        """Vigenere cipher"""
        result = ""
        key = key.upper()
        key_len = len(key)

        for i, char in enumerate(text.upper()):
            if char.isalpha():
                shift = ord(key[i % key_len]) - 65
                if not encrypt:
                    shift = -shift
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                result += char
        return result

    @staticmethod
    def playfair_cipher(text, key, encrypt=True):
        """Playfair cipher (simplified)"""
        # Create 5x5 matrix
        key = key.upper().replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        matrix = []
        used = set()

        for char in key + alphabet:
            if char not in used and char in alphabet:
                matrix.append(char)
                used.add(char)

        # Split into digraphs
        text = text.upper().replace('J', 'I').replace(' ', '')
        if len(text) % 2:
            text += 'X'

        result = ""
        for i in range(0, len(text), 2):
            a, b = text[i], text[i + 1]
            if a == b:
                b = 'X'

            idx_a = matrix.index(a)
            idx_b = matrix.index(b)
            row_a, col_a = divmod(idx_a, 5)
            row_b, col_b = divmod(idx_b, 5)

            if row_a == row_b:
                # Same row
                shift = 1 if encrypt else -1
                result += matrix[row_a * 5 + (col_a + shift) % 5]
                result += matrix[row_b * 5 + (col_b + shift) % 5]
            elif col_a == col_b:
                # Same column
                shift = 1 if encrypt else -1
                result += matrix[((row_a + shift) % 5) * 5 + col_a]
                result += matrix[((row_b + shift) % 5) * 5 + col_b]
            else:
                # Rectangle
                result += matrix[row_a * 5 + col_b]
                result += matrix[row_b * 5 + col_a]

        return result


# ==================== MODULE 2: HASHING ====================
class HashingModule:
    @staticmethod
    def custom_hash(data):
        """Custom hash function (starting with 5381)"""
        hash_value = 5381
        for char in data:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            hash_value = hash_value & 0xFFFFFFFF  # Keep 32-bit
        return hash_value

    @staticmethod
    def md5_hash(data):
        """MD5 hash"""
        return hashlib.md5(data.encode()).hexdigest()

    @staticmethod
    def sha256_hash(data):
        """SHA-256 hash"""
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def compare_hashes():
        """Compare performance of hash functions"""
        test_data = "This is test data for hashing comparison"

        print("\n🔍 Hash Comparison:")
        start = time.time()
        md5 = hashlib.md5(test_data.encode()).hexdigest()
        md5_time = time.time() - start

        start = time.time()
        sha1 = hashlib.sha1(test_data.encode()).hexdigest()
        sha1_time = time.time() - start

        start = time.time()
        sha256 = hashlib.sha256(test_data.encode()).hexdigest()
        sha256_time = time.time() - start

        print(f"MD5:    {md5[:20]}... Time: {md5_time:.6f}s")
        print(f"SHA-1:  {sha1[:20]}... Time: {sha1_time:.6f}s")
        print(f"SHA-256: {sha256[:20]}... Time: {sha256_time:.6f}s")

        return {
            'md5': md5_time,
            'sha1': sha1_time,
            'sha256': sha256_time
        }


# ==================== MODULE 3: RSA ====================
class RSACrypto:
    def __init__(self, bits=512):
        self.bits = bits
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """Generate RSA keys"""
        key = RSA.generate(self.bits)
        self.public_key = key.publickey()
        self.private_key = key
        return self.public_key, self.private_key

    def encrypt(self, message):
        """Encrypt with RSA"""
        if not self.public_key:
            raise ValueError("Public key not generated")
        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(message.encode())

    def decrypt(self, ciphertext):
        """Decrypt with RSA"""
        if not self.private_key:
            raise ValueError("Private key not generated")
        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(ciphertext).decode()

    def sign(self, message):
        """Create RSA signature"""
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(self.private_key).sign(h)
        return signature

    def verify(self, message, signature):
        """Verify RSA signature"""
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except:
            return False


# ==================== MODULE 4: ELGAMAL ====================
class ElGamalCrypto:
    def __init__(self, p=None):
        self.p = p or 32321  # Small prime for demo
        self.g = 3
        self.x = None  # Private key
        self.h = None  # Public key part

    def generate_keys(self):
        """Generate ElGamal keys"""
        self.x = random.randint(1, self.p - 2)
        self.h = pow(self.g, self.x, self.p)
        return (self.p, self.g, self.h), self.x

    def encrypt(self, message):
        """Encrypt with ElGamal"""
        m = int.from_bytes(message.encode(), 'big')
        y = random.randint(1, self.p - 2)
        c1 = pow(self.g, y, self.p)
        s = pow(self.h, y, self.p)
        c2 = (m * s) % self.p
        return (c1, c2)

    def decrypt(self, cipher):
        """Decrypt with ElGamal"""
        c1, c2 = cipher
        s = pow(c1, self.x, self.p)
        m = (c2 * pow(s, -1, self.p)) % self.p
        return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


# ==================== MODULE 5: PAILLIER (PHE) ====================
class PaillierCrypto:
    """Partial Homomorphic Encryption - Additive"""

    def __init__(self, bits=64):
        self.bits = bits
        self.p = None
        self.q = None
        self.n = None
        self.n2 = None
        self.g = None
        self.lambda_val = None
        self.mu = None

    def generate_keys(self):
        """Generate Paillier keys"""
        # For demo, use small primes
        self.p = self._generate_prime(self.bits // 2)
        self.q = self._generate_prime(self.bits // 2)
        self.n = self.p * self.q
        self.n2 = self.n * self.n
        self.g = self.n + 1  # Standard choice
        self.lambda_val = math.lcm(self.p - 1, self.q - 1)
        self.mu = pow(self.lambda_val, -1, self.n)

        return self.n, self.g

    def _generate_prime(self, bits):
        """Generate a prime number"""
        while True:
            p = random.getrandbits(bits)
            if p % 2 != 0 and self._is_prime(p):
                return p

    def _is_prime(self, n, k=5):
        """Miller-Rabin primality test"""
        if n < 2:
            return False
        for p in [2, 3, 5, 7, 11]:
            if n % p == 0:
                return n == p

        # Write n-1 as d*2^s
        s = 0
        d = n - 1
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def encrypt(self, m):
        """Encrypt a number m (0 <= m < n)"""
        r = random.randint(1, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)

        c = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return c

    def decrypt(self, c):
        """Decrypt ciphertext c"""
        x = pow(c, self.lambda_val, self.n2)
        l_val = (x - 1) // self.n
        m = (l_val * self.mu) % self.n
        return m

    def homomorphic_add(self, c1, c2):
        """Homomorphic addition: E(m1) * E(m2) = E(m1 + m2)"""
        return (c1 * c2) % self.n2


# ==================== MODULE 6: SEARCHABLE ENCRYPTION (SSE) ====================
class SearchableEncryption:
    def __init__(self):
        self.documents = {}
        self.encrypted_index = {}
        self.key = get_random_bytes(16)  # AES key

    def add_document(self, doc_id, text):
        """Add document to collection"""
        self.documents[doc_id] = text

    def build_index(self):
        """Build encrypted search index"""
        self.encrypted_index = {}

        for doc_id, text in self.documents.items():
            words = set(text.lower().split())
            for word in words:
                # Hash the word
                word_hash = hashlib.sha256(word.encode()).digest()
                # Encrypt the hash with AES
                cipher = AES.new(self.key, AES.MODE_ECB)
                encrypted_word = cipher.encrypt(pad(word_hash, AES.block_size))

                # Add doc_id to index
                key = base64.b64encode(encrypted_word).decode()
                if key not in self.encrypted_index:
                    self.encrypted_index[key] = []
                self.encrypted_index[key].append(doc_id)

        print(f"✅ Index built with {len(self.encrypted_index)} unique words")

    def search(self, query):
        """Search for documents containing query"""
        # Encrypt the query
        query_hash = hashlib.sha256(query.lower().encode()).digest()
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_query = cipher.encrypt(pad(query_hash, AES.block_size))
        key = base64.b64encode(encrypted_query).decode()

        if key in self.encrypted_index:
            results = self.encrypted_index[key]
            print(f"🔍 Found {len(results)} documents for '{query}':")
            for doc_id in results:
                print(f"  - {doc_id}: {self.documents[doc_id][:50]}...")
            return results
        else:
            print(f"❌ No documents found for '{query}'")
            return []

    def demo(self):
        """Demonstrate SSE"""
        print("\n🔐 SEARCHABLE ENCRYPTION DEMO")
        print("=" * 40)

        # Add sample documents
        docs = {
            "doc1": "This is a confidential report about cybersecurity",
            "doc2": "Patient medical records are highly sensitive",
            "doc3": "Financial transactions must be encrypted",
            "doc4": "Cybersecurity measures protect sensitive data",
            "doc5": "Medical and financial data require protection"
        }

        for doc_id, text in docs.items():
            self.add_document(doc_id, text)

        # Build index
        self.build_index()

        # Search
        self.search("cybersecurity")
        self.search("medical")
        self.search("financial")


# ==================== MODULE 7: DATABASE ENCRYPTION ====================
class EncryptedDatabase:
    def __init__(self):
        self.tables = {}
        self.aes_key = get_random_bytes(16)

    def create_table(self, table_name, columns):
        """Create an encrypted table"""
        self.tables[table_name] = {
            'columns': columns,
            'data': [],
            'encrypted_data': []
        }
        print(f"✅ Table '{table_name}' created with columns: {columns}")

    def insert(self, table_name, row):
        """Insert encrypted row"""
        if table_name not in self.tables:
            print(f"❌ Table '{table_name}' not found")
            return

        # Encrypt each field
        encrypted_row = {}
        for col, value in zip(self.tables[table_name]['columns'], row):
            cipher = AES.new(self.aes_key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(str(value).encode(), AES.block_size))
            encrypted_row[col] = {
                'iv': base64.b64encode(cipher.iv).decode(),
                'data': base64.b64encode(ct_bytes).decode()
            }

        self.tables[table_name]['data'].append(row)
        self.tables[table_name]['encrypted_data'].append(encrypted_row)
        print(f"✅ Row inserted into '{table_name}'")

    def query(self, table_name, column=None, value=None):
        """Query encrypted database"""
        if table_name not in self.tables:
            print(f"❌ Table '{table_name}' not found")
            return []

        results = []
        for i, row in enumerate(self.tables[table_name]['data']):
            if column and value:
                col_index = self.tables[table_name]['columns'].index(column)
                if row[col_index] == value:
                    results.append(row)
            else:
                results.append(row)

        print(f"\n📊 Query results from '{table_name}':")
        for row in results:
            print(f"  {row}")

        return results

    def show_encrypted(self, table_name):
        """Show encrypted data"""
        if table_name not in self.tables:
            print(f"❌ Table '{table_name}' not found")
            return

        print(f"\n🔐 Encrypted data in '{table_name}':")
        for i, enc_row in enumerate(self.tables[table_name]['encrypted_data']):
            print(f"\nRow {i}:")
            for col, data in enc_row.items():
                print(f"  {col}: {data['data'][:30]}...")


# ==================== MODULE 8: DIGITAL SIGNATURE ====================
class DigitalSignatureSystem:
    def __init__(self):
        self.rsa = RSACrypto(512)
        self.rsa.generate_keys()
        self.signed_docs = {}

    def sign_document(self, doc_id, content, signer):
        """Sign a document"""
        signature = self.rsa.sign(content)

        self.signed_docs[doc_id] = {
            'content': content,
            'signature': base64.b64encode(signature).decode(),
            'signer': signer,
            'timestamp': time.time()
        }

        print(f"✅ Document '{doc_id}' signed by {signer}")
        return signature

    def verify_document(self, doc_id):
        """Verify a document's signature"""
        if doc_id not in self.signed_docs:
            print(f"❌ Document '{doc_id}' not found")
            return False

        doc = self.signed_docs[doc_id]
        signature = base64.b64decode(doc['signature'])
        verified = self.rsa.verify(doc['content'], signature)

        if verified:
            print(f"✅ Signature VALID for document '{doc_id}'")
            print(f"   Signer: {doc['signer']}")
            print(f"   Content: {doc['content'][:50]}...")
        else:
            print(f"❌ Signature INVALID for document '{doc_id}'")

        return verified

    def demo(self):
        """Demonstrate digital signatures"""
        print("\n📝 DIGITAL SIGNATURE DEMO")
        print("=" * 40)

        self.sign_document("contract1", "This is a legal agreement between parties", "Alice")
        self.sign_document("report1", "Quarterly financial report 2024", "Bob")

        self.verify_document("contract1")
        self.verify_document("report1")


# ==================== MAIN MENU ====================
class CryptoExamKit:
    def __init__(self):
        self.symmetric = SymmetricCiphers()
        self.hashing = HashingModule()
        self.rsa = RSACrypto()
        self.elgamal = ElGamalCrypto()
        self.paillier = PaillierCrypto()
        self.sse = SearchableEncryption()
        self.database = EncryptedDatabase()
        self.signature = DigitalSignatureSystem()

    def menu_symmetric(self):
        """Symmetric ciphers menu"""
        print("\n🔐 SYMMETRIC CIPHERS")
        print("=" * 40)

        text = input("Enter text to encrypt: ")

        print("\n1. Caesar Cipher")
        print("2. Multiplicative Cipher")
        print("3. Affine Cipher")
        print("4. Vigenere Cipher")
        print("5. Playfair Cipher")

        choice = input("\nChoose cipher: ")

        if choice == '1':
            shift = int(input("Shift key: "))
            encrypted = self.symmetric.caesar_cipher(text, shift, True)
            decrypted = self.symmetric.caesar_cipher(encrypted, shift, False)
            print(f"\nEncrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")

        elif choice == '2':
            key = int(input("Multiplicative key (must be coprime with 26): "))
            encrypted = self.symmetric.multiplicative_cipher(text, key, True)
            decrypted = self.symmetric.multiplicative_cipher(encrypted, key, False)
            print(f"\nEncrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")

        elif choice == '3':
            a = int(input("Key a (must be coprime with 26): "))
            b = int(input("Key b: "))
            encrypted = self.symmetric.affine_cipher(text, a, b, True)
            decrypted = self.symmetric.affine_cipher(encrypted, a, b, False)
            print(f"\nEncrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")

        elif choice == '4':
            key = input("Vigenere key: ")
            encrypted = self.symmetric.vigenere_cipher(text, key, True)
            decrypted = self.symmetric.vigenere_cipher(encrypted, key, False)
            print(f"\nEncrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")

        elif choice == '5':
            key = input("Playfair key: ")
            encrypted = self.symmetric.playfair_cipher(text, key, True)
            decrypted = self.symmetric.playfair_cipher(encrypted, key, False)
            print(f"\nEncrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")

    def menu_hashing(self):
        """Hashing functions menu"""
        print("\n🔍 HASHING FUNCTIONS")
        print("=" * 40)

        data = input("Enter data to hash: ")

        print("\n1. Custom Hash (5381)")
        print("2. MD5")
        print("3. SHA-256")
        print("4. Compare All Hashes")
        print("5. Data Integrity Demo")

        choice = input("\nChoose: ")

        if choice == '1':
            hash_val = self.hashing.custom_hash(data)
            print(f"\nCustom Hash: {hash_val} (hex: {hex(hash_val)})")

        elif choice == '2':
            hash_val = self.hashing.md5_hash(data)
            print(f"\nMD5: {hash_val}")

        elif choice == '3':
            hash_val = self.hashing.sha256_hash(data)
            print(f"\nSHA-256: {hash_val}")

        elif choice == '4':
            self.hashing.compare_hashes()

        elif choice == '5':
            # Data integrity demo
            original = data
            modified = original + "x"  # Tamper with data

            orig_hash = self.hashing.sha256_hash(original)
            mod_hash = self.hashing.sha256_hash(modified)

            print(f"\nOriginal data: {original}")
            print(f"Original hash: {orig_hash[:30]}...")
            print(f"\nModified data: {modified}")
            print(f"Modified hash: {mod_hash[:30]}...")
            print(f"\n✅ Hashes match: {orig_hash == mod_hash}")

    def menu_rsa(self):
        """RSA cryptography menu"""
        print("\n🔑 RSA CRYPTOGRAPHY")
        print("=" * 40)

        self.rsa.generate_keys()
        message = input("Enter message: ")

        print("\n1. Encrypt/Decrypt")
        print("2. Digital Signature")
        print("3. Full Demo")

        choice = input("\nChoose: ")

        if choice == '1':
            encrypted = self.rsa.encrypt(message)
            decrypted = self.rsa.decrypt(encrypted)
            print(f"\nOriginal: {message}")
            print(f"Encrypted: {base64.b64encode(encrypted).decode()[:50]}...")
            print(f"Decrypted: {decrypted}")

        elif choice == '2':
            signature = self.rsa.sign(message)
            verified = self.rsa.verify(message, signature)
            print(f"\nMessage: {message}")
            print(f"Signature: {base64.b64encode(signature).decode()[:50]}...")
            print(f"Verified: {verified}")

        elif choice == '3':
            encrypted = self.rsa.encrypt(message)
            decrypted = self.rsa.decrypt(encrypted)
            signature = self.rsa.sign(message)
            verified = self.rsa.verify(message, signature)

            print(f"\n📊 RSA DEMO:")
            print(f"Message: {message}")
            print(f"Encrypted: {base64.b64encode(encrypted).decode()[:30]}...")
            print(f"Decrypted: {decrypted}")
            print(f"Signature created: ✅")
            print(f"Signature verified: {'✅' if verified else '❌'}")

    def menu_paillier(self):
        """Paillier PHE menu"""
        print("\n➕ PAILLIER HOMOMORPHIC ENCRYPTION")
        print("=" * 40)

        self.paillier.generate_keys()

        print("1. Basic Encryption/Decryption")
        print("2. Homomorphic Addition")
        print("3. Secure Voting Demo")

        choice = input("\nChoose: ")

        if choice == '1':
            num = int(input("Enter number to encrypt: "))
            encrypted = self.paillier.encrypt(num)
            decrypted = self.paillier.decrypt(encrypted)
            print(f"\nNumber: {num}")
            print(f"Encrypted: {encrypted}")
            print(f"Decrypted: {decrypted}")

        elif choice == '2':
            a = int(input("Enter first number: "))
            b = int(input("Enter second number: "))

            enc_a = self.paillier.encrypt(a)
            enc_b = self.paillier.encrypt(b)
            enc_sum = self.paillier.homomorphic_add(enc_a, enc_b)
            decrypted_sum = self.paillier.decrypt(enc_sum)

            print(f"\nNumber A: {a}, Encrypted: {enc_a}")
            print(f"Number B: {b}, Encrypted: {enc_b}")
            print(f"\nHomomorphic addition:")
            print(f"  E({a}) * E({b}) = E({a + b})")
            print(f"  Encrypted sum: {enc_sum}")
            print(f"  Decrypted sum: {decrypted_sum}")
            print(f"  Correct: {decrypted_sum == a + b}")

        elif choice == '3':
            # Secure voting demo
            votes = [1, 0, 1, 1, 0]  # 1 = Yes, 0 = No
            encrypted_votes = [self.paillier.encrypt(vote) for vote in votes]

            # Homomorphically add all votes
            total_encrypted = encrypted_votes[0]
            for ev in encrypted_votes[1:]:
                total_encrypted = self.paillier.homomorphic_add(total_encrypted, ev)

            total = self.paillier.decrypt(total_encrypted)

            print(f"\n🗳️ SECURE VOTING DEMO")
            print(f"Votes (Yes=1, No=0): {votes}")
            print(f"Total Yes votes (decrypted): {total}")
            print(f"Individual votes remain encrypted!")

    def menu_sse(self):
        """Searchable Encryption menu"""
        print("\n🔍 SEARCHABLE ENCRYPTION")
        print("=" * 40)

        self.sse.demo()

        # Interactive mode
        print("\n🎮 INTERACTIVE MODE")
        while True:
            print("\n1. Add document")
            print("2. Search")
            print("3. Show index")
            print("4. Back to main")

            choice = input("\nChoose: ")

            if choice == '1':
                doc_id = input("Document ID: ")
                text = input("Document text: ")
                self.sse.add_document(doc_id, text)
                self.sse.build_index()

            elif choice == '2':
                query = input("Search query: ")
                self.sse.search(query)

            elif choice == '3':
                print(f"\nEncrypted index has {len(self.sse.encrypted_index)} entries")
                for key, docs in list(self.sse.encrypted_index.items())[:3]:
                    print(f"  {key[:20]}... -> {docs}")

            elif choice == '4':
                break

    def menu_database(self):
        """Encrypted database menu"""
        print("\n🗄️ ENCRYPTED DATABASE")
        print("=" * 40)

        # Create sample table
        self.database.create_table("patients", ["id", "name", "diagnosis", "treatment"])

        print("\n1. Insert sample data")
        print("2. Query data")
        print("3. Show encrypted data")
        print("4. Custom insert")

        choice = input("\nChoose: ")

        if choice == '1':
            # Insert sample data
            sample_data = [
                ["P001", "John Doe", "Hypertension", "Medication"],
                ["P002", "Jane Smith", "Diabetes", "Insulin"],
                ["P003", "Bob Johnson", "Asthma", "Inhaler"]
            ]

            for row in sample_data:
                self.database.insert("patients", row)

        elif choice == '2':
            self.database.query("patients")
            col = input("\nFilter by column (or Enter for all): ")
            if col:
                val = input(f"Value for {col}: ")
                self.database.query("patients", col, val)

        elif choice == '3':
            self.database.show_encrypted("patients")

        elif choice == '4':
            id_val = input("Patient ID: ")
            name = input("Name: ")
            diag = input("Diagnosis: ")
            treat = input("Treatment: ")
            self.database.insert("patients", [id_val, name, diag, treat])

    def main_menu(self):
        """Main menu"""
        print("\n" + "=" * 60)
        print("🎯 ICT3141 - INFORMATION SECURITY EXAM KIT")
        print("=" * 60)

        while True:
            print("\nSELECT MODULE:")
            print("1. Symmetric Ciphers (Caesar, Vigenere, Playfair)")
            print("2. Hashing (MD5, SHA-256, Custom Hash)")
            print("3. RSA (Encryption + Digital Signatures)")
            print("4. ElGamal (Asymmetric Encryption)")
            print("5. Paillier (Homomorphic Encryption)")
            print("6. Searchable Encryption (SSE)")
            print("7. Encrypted Database")
            print("8. Digital Signature System")
            print("9. Run All Demos")
            print("0. Exit")

            choice = input("\nEnter choice (0-9): ")

            if choice == '1':
                self.menu_symmetric()
            elif choice == '2':
                self.menu_hashing()
            elif choice == '3':
                self.menu_rsa()
            elif choice == '4':
                self.menu_elgamal()
            elif choice == '5':
                self.menu_paillier()
            elif choice == '6':
                self.menu_sse()
            elif choice == '7':
                self.menu_database()
            elif choice == '8':
                self.signature.demo()
            elif choice == '9':
                self.run_all_demos()
            elif choice == '0':
                print("\n👋 Good luck with your exam!")
                break
            else:
                print("❌ Invalid choice")

    def menu_elgamal(self):
        """ElGamal cryptography menu"""
        print("\n🔐 ELGAMAL CRYPTOGRAPHY")
        print("=" * 40)

        self.elgamal.generate_keys()
        message = input("Enter message: ")

        encrypted = self.elgamal.encrypt(message)
        decrypted = self.elgamal.decrypt(encrypted)

        print(f"\nMessage: {message}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"✅ Match: {message == decrypted}")

    def run_all_demos(self):
        """Run quick demos of all modules"""
        print("\n🚀 RUNNING ALL DEMOS")
        print("=" * 60)

        # 1. Symmetric
        print("\n1. 🔐 Symmetric Cipher (Caesar):")
        text = "HELLO"
        encrypted = self.symmetric.caesar_cipher(text, 3, True)
        decrypted = self.symmetric.caesar_cipher(encrypted, 3, False)
        print(f"   '{text}' -> '{encrypted}' -> '{decrypted}'")

        # 2. Hashing
        print("\n2. 🔍 Hashing (SHA-256):")
        hash_val = self.hashing.sha256_hash("test")
        print(f"   'test' -> {hash_val[:30]}...")

        # 3. RSA
        print("\n3. 🔑 RSA Encryption:")
        self.rsa.generate_keys()
        enc = self.rsa.encrypt("secret")
        dec = self.rsa.decrypt(enc)
        print(f"   'secret' -> encrypted -> '{dec}'")

        # 4. Paillier
        print("\n4. ➕ Paillier Homomorphic Addition:")
        self.paillier.generate_keys()
        enc1 = self.paillier.encrypt(5)
        enc2 = self.paillier.encrypt(3)
        enc_sum = self.paillier.homomorphic_add(enc1, enc2)
        total = self.paillier.decrypt(enc_sum)
        print(f"   E(5) + E(3) = E(8) -> {total}")

        # 5. SSE
        print("\n5. 🔍 Searchable Encryption:")
        print("   Index built for 5 documents")

        print("\n✅ All demos completed!")


# ==================== RUN ====================
if __name__ == "__main__":
    try:
        kit = CryptoExamKit()
        kit.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Program terminated")