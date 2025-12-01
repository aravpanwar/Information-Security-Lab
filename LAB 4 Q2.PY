# Lab 4 Q2 - Rabin Cryptosystem Key Management for Healthcare
import random, hashlib, json, time
from sympy import nextprime


class RabinKMS:
    def __init__(self):
        self.keys = {}  # facility: {'pub': n, 'priv': (p,q), 'created': timestamp}
        self.revoked = set()
        self.log = []

    def log_event(self, event):
        self.log.append(f"{time.ctime()}: {event}")
        print(f"LOG: {event}")

    def generate_keys(self, facility, bits=1024):
        # Generate two primes p,q ≡ 3 mod 4
        half = bits // 2
        p = self.get_blum_prime(half)
        q = self.get_blum_prime(half)
        n = p * q
        self.keys[facility] = {'pub': n, 'priv': (p, q), 'created': time.time()}
        self.log_event(f"Generated keys for {facility}")
        return {'public': n, 'private': (p, q)}

    def get_blum_prime(self, bits):
        while True:
            p = nextprime(random.getrandbits(bits))
            if p % 4 == 3:
                return p

    def distribute_keys(self, facility):
        if facility in self.revoked:
            return "Key revoked"
        if facility not in self.keys:
            return "No keys"
        self.log_event(f"Distributed keys to {facility}")
        return {'public': self.keys[facility]['pub']}

    def revoke_keys(self, facility):
        if facility in self.keys:
            self.revoked.add(facility)
            del self.keys[facility]
            self.log_event(f"Revoked keys for {facility}")
            return f"Revoked {facility}"
        return "Facility not found"

    def renew_keys(self):
        renewed = []
        for facility in list(self.keys.keys()):
            if facility not in self.revoked:
                age = time.time() - self.keys[facility]['created']
                if age > 30:  # Simplified: renew after 30 seconds for demo
                    self.generate_keys(facility)
                    renewed.append(facility)
        self.log_event(f"Renewed keys for: {renewed}")
        return renewed

    def encrypt(self, n, message):
        m = int.from_bytes(message.encode(), 'big') % n
        return pow(m, 2, n)

    def decrypt(self, ciphertext, p, q):
        n = p * q
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)
        # Simplified: return first root
        return min(mp, mq, n - mp, n - mq)


print("Healthcare Inc. - Rabin KMS")
print("=" * 40)

kms = RabinKMS()

# 1. Key Generation
print("\n1. Generating keys for hospitals:")
h1 = kms.generate_keys("General Hospital", 512)  # Smaller for speed
h2 = kms.generate_keys("City Clinic", 512)
print(f"   General Hospital - Public key: {h1['public']}")
print(f"   City Clinic - Public key: {h2['public']}")

# 2. Key Distribution
print("\n2. Distributing keys:")
print(f"   General Hospital gets: {kms.distribute_keys('General Hospital')}")
print(f"   City Clinic gets: {kms.distribute_keys('City Clinic')}")

# 3. Encryption/Decryption demo
print("\n3. Encrypting patient record:")
msg = "Patient: John Doe, BP: 120/80"
n = h1['public']
p, q = h1['private']
ct = kms.encrypt(n, msg)
pt_num = kms.decrypt(ct, p, q)
pt = pt_num.to_bytes((pt_num.bit_length() + 7) // 8, 'big').decode()
print(f"   Original: {msg}")
print(f"   Ciphertext: {ct}")
print(f"   Decrypted: {pt[:20]}...")

# 4. Key Revocation
print("\n4. Revoking City Clinic keys:")
print(f"   Result: {kms.revoke_keys('City Clinic')}")
print(f"   Try distribute revoked: {kms.distribute_keys('City Clinic')}")

# 5. Key Renewal
print("\n5. Auto-renewal check:")
time.sleep(0.1)  # Simulate time passing
renewed = kms.renew_keys()
print(f"   Renewed: {renewed}")

# 6. Logs
print("\n6. Audit Log (last 2 entries):")
for entry in kms.log[-2:]:
    print(f"   {entry}")

# 7. Rabin vs RSA Trade-off
print("\n" + "=" * 40)
print("RABIN vs RSA TRADE-OFF ANALYSIS")
print("• Rabin: Faster encryption (squaring), but decryption yields 4 roots")
print("• RSA: Slower encryption (modular exp), unique decryption")
print("• Rabin security = factoring, RSA security = factoring + more")
print("• Rabin better for signatures, RSA better for encryption")
print("• For healthcare: Rabin faster but needs extra validation")