# Lab 6 - Diffie-Hellman with Signatures
import random
from Crypto.Util.number import getPrime, inverse
import hashlib

def dh_keygen(bits=256):
    """Generate DH parameters and keys"""
    p = getPrime(bits)
    g = random.randint(2, p-2)
    private = random.randint(1, p-2)
    public = pow(g, private, p)
    return (p, g), private, public

def dh_shared_secret(private, other_public, p):
    """Compute shared secret"""
    return pow(other_public, private, p)

def sign_message(message, private_key, p, g):
    """Simulate signing using DH-derived key"""
    # Derive signing key from private key
    sign_key = hashlib.sha256(str(private_key).encode()).hexdigest()[:16]
    # Simple signature simulation
    signature = hashlib.sha256((message + sign_key).encode()).hexdigest()[:32]
    return signature

def verify_signature(message, signature, public_key, p, g):
    """Simulate verification"""
    # Derive verification key from public key
    verify_key = hashlib.sha256(str(public_key).encode()).hexdigest()[:16]
    expected = hashlib.sha256((message + verify_key).encode()).hexdigest()[:32]
    return signature == expected

print("DIFFIE-HELLMAN WITH SIGNATURES")
print("=" * 40)

# Step 1: Generate parameters
print("1. DH Parameter Generation:")
params, alice_priv, alice_pub = dh_keygen(128)
p, g = params
_, bob_priv, bob_pub = dh_keygen(128)
print(f"   p = {p}")
print(f"   g = {g}")
print(f"   Alice public: {alice_pub}")
print(f"   Bob public: {bob_pub}")

# Step 2: Compute shared secret
print("\n2. Shared Secret Computation:")
alice_shared = dh_shared_secret(alice_priv, bob_pub, p)
bob_shared = dh_shared_secret(bob_priv, alice_pub, p)
print(f"   Alice shared: {alice_shared}")
print(f"   Bob shared: {bob_shared}")
print(f"   Match: {alice_shared == bob_shared}")

# Step 3: Alice signs document
print("\n3. Alice signs 'Contract v1.0':")
doc1 = "Contract v1.0"
sig1 = sign_message(doc1, alice_priv, p, g)
print(f"   Document: {doc1}")
print(f"   Signature: {sig1[:16]}...")

# Step 4: Bob verifies
print("\n4. Bob verifies Alice's signature:")
valid1 = verify_signature(doc1, sig1, alice_pub, p, g)
print(f"   Valid: {valid1}")

# Step 5: Bob signs response
print("\n5. Bob signs 'Accepted - BOB':")
doc2 = "Accepted - BOB"
sig2 = sign_message(doc2, bob_priv, p, g)
print(f"   Response: {doc2}")
print(f"   Signature: {sig2[:16]}...")

# Step 6: Alice verifies Bob's signature
print("\n6. Alice verifies Bob's signature:")
valid2 = verify_signature(doc2, sig2, bob_pub, p, g)
print(f"   Valid: {valid2}")

# Step 7: Tampering test
print("\n7. Tampering detection test:")
tampered = "Contract v2.0"
valid3 = verify_signature(tampered, sig1, alice_pub, p, g)
print(f"   Tampered document: {tampered}")
print(f"   Original signature valid: {valid3}")
print(f"   Tampering detected: {not valid3}")

print("\n" + "=" * 40)
print("DH key exchange + signature verification")