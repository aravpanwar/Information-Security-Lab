# Lab 4 Q1 - SecureCorp Communication System
import random, hashlib, json, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


class SecureSystem:
    def __init__(self, name):
        self.name = name
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.private_key = self.rsa_key
        self.shared_secrets = {}  # System name -> shared key

    def get_dh_public(self, p, g):
        self.dh_private = random.randint(2, p - 2)
        self.dh_public = pow(g, self.dh_private, p)
        return self.dh_public

    def compute_shared_secret(self, other_public, p, system_name):
        shared = pow(other_public, self.dh_private, p)
        # Convert to AES key
        key = hashlib.sha256(str(shared).encode()).digest()[:16]
        self.shared_secrets[system_name] = key
        return key

    def send_message(self, receiver_name, message):
        if receiver_name not in self.shared_secrets:
            return "No shared key established"
        key = self.shared_secrets[receiver_name]
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ct, tag = cipher.encrypt_and_digest(message.encode())
        return json.dumps({'nonce': nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex()})

    def receive_message(self, sender_name, encrypted_msg):
        if sender_name not in self.shared_secrets:
            return "No shared key"
        key = self.shared_secrets[sender_name]
        data = json.loads(encrypted_msg)
        cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(data['nonce']))
        pt = cipher.decrypt_and_verify(bytes.fromhex(data['ct']), bytes.fromhex(data['tag']))
        return pt.decode()


print("SecureCorp Communication System")
print("=" * 40)

# Create subsystems
finance = SecureSystem("Finance")
hr = SecureSystem("HR")
supply = SecureSystem("SupplyChain")

print("Systems created: Finance, HR, SupplyChain")

# Diffie-Hellman between Finance and HR
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381
g = 2

print("\n1. DH Key Exchange (Finance ↔ HR)")
f_public = finance.get_dh_public(p, g)
h_public = hr.get_dh_public(p, g)
finance.compute_shared_secret(h_public, p, "HR")
hr.compute_shared_secret(f_public, p, "Finance")
print("   Shared key established")

# Send message
print("\n2. Finance sends encrypted message to HR")
msg = "Monthly financial report: $1.2M revenue"
enc = finance.send_message("HR", msg)
dec = hr.receive_message("Finance", enc)
print(f"   Original: {msg}")
print(f"   Encrypted: {enc[:50]}...")
print(f"   Decrypted: {dec}")

# Key management
print("\n3. Key Management")
print(f"   Finance has keys for: {list(finance.shared_secrets.keys())}")
print(f"   HR has keys for: {list(hr.shared_secrets.keys())}")

# Scalability: Add new system
print("\n4. Adding new subsystem (IT)")
it = SecureSystem("IT")
print("   IT system added successfully")
print(f"   Total systems: Finance, HR, SupplyChain, IT")